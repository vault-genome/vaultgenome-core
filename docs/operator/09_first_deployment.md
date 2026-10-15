# First deployment

**When to read this:** before the first deployment of a release on a real
host. **Who:** the Vault operator, with the compute-plane operator for the
worker host. **What it gives:** a deployment whose every step is compared
with the reference deployment the project keeps — a signed release,
verified, run on real SEV-SNP and recorded — so that the first deployment
has something to be measured against, not only instructions to follow.

The reference is `scripts/hardware-test/release-deploy/`: one command
downloads a release's assets, verifies every signature, the SLSA provenance
and the tag, rebuilds the binaries from the tag and requires the hashes to
equal the released files, then runs the Return Path on a fresh SEV-SNP
Confidential VM with the released daemons and records what the guest did.
Its record of `v0.4.2` is
[`evidence/20261015T170743Z/`](../../scripts/hardware-test/release-deploy/evidence/20261015T170743Z/README.md)
— the first in which nothing came from the source tree: the key helper,
the worker package and the AMD chain are the release's too; the numbers
below are that record's. A first deployment that reproduces them is on the
reference path; one that does not has found something worth stopping for.

---

## 1. Verify the release before it runs anywhere

Nothing from a release runs until its assets verify. Download all 49 assets
of the release (the five binaries, the worker package, their six SBOMs, a
signature, a certificate and a Sigstore bundle for each of those twelve,
and the SLSA provenance; 37 for 0.4.2, which has no bundles) to a clean
machine and run, for each of `sagvd`, `acp-compute`, `acpctl`,
`acp-bootstrap`, `acp-keygen` and the worker package
`genome-worker-<tag>.tar.gz`:

```bash
cosign verify-blob --signature sagvd.sig --certificate sagvd.cert \
  --certificate-identity-regexp '^https://github\.com/vault-genome/vaultgenome-core/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com sagvd
slsa-verifier verify-artifact sagvd --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/vault-genome/vaultgenome-core --source-tag v0.4.2
```

and the same `cosign verify-blob` for each `*.sbom.spdx.json` with its
`.sbom.sig` and `.sbom.cert`. The bundle checks the same thing from one
file, and does it without a route to Rekor once `cosign initialize` has
cached the Sigstore trust root (while connected): `cosign verify-blob
--bundle sagvd.sigstore.json --offline` with the same two identity flags
— the check an air-gapped site runs
([runbooks/air_gap.md](runbooks/air_gap.md)). Then the tag, against the
keys pinned on `main`, never against keys in the tagged tree:

```bash
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag v0.4.2
```

| Check | What the reference saw for `v0.4.2` | Where |
| - | - | - |
| cosign, artifacts and SBOMs | twelve `Verified OK` (eight for `v0.4.1`, which had four artifacts) | `verify/cosign.txt` |
| slsa-verifier, the artifacts | six `PASSED: SLSA verification passed` (four for `v0.4.1`) | `verify/slsa.txt` |
| the tag | `Good "git" signature` with the ED25519 key of `.github/allowed_signers` | `verify/tag.txt` |
| the assets' hashes | 37 lines (25 for `v0.4.1`) | `verify/assets.sha256` |
| rebuilt from the tag on another machine | every sha256 equal to the released file's: the five binaries, and the worker package repacked with GNU tar and GNU gzip | `verify/rebuild.txt` |
| uploaded to the guest | five files, every one a release asset: `sagvd`, `acp-compute`, `acpctl`, `acp-keygen` (as `keygen`) and the worker package; the AMD chain fetched on the guest by the released `acpctl` and checked against the pinned root (`results/amd-chain.txt`) | `verify/uploaded.sha256`, `verify/tools.txt` |

The hashes in `verify/assets.sha256` are the hashes of the files you
downloaded, or you have different files. The rebuild is the release
procedure's §5.4 ([05](05_release_procedure.md)); the kit does it by
itself, and an operator with a Go toolchain can repeat it from a checkout
of the tag. `docs/security/supply_chain.md` says what each check proves.
If you have a GCP project, run the kit itself and compare its record with
the one in the tree:

```bash
./scripts/hardware-test/release-deploy/run.sh <gcp-project> v0.4.2
```

About fifteen minutes and one `n2d-standard-4`, created and deleted by the
run.

## 2. Choose the host

The daemons attest with the TEE they run on, and refuse to run on hardware
they cannot attest. What a release can run on today
([KNOWN_ISSUES.md](../../KNOWN_ISSUES.md) #1):

| Host | `tee.provider` | Proven by |
| - | - | - |
| GCP `n2d` Confidential VM, AMD SEV-SNP (Milan) | `gcp-sev-snp` | the reference deployment; `gcp-sev-snp/returnpath-e2e`; the failover drills (C8, C14, C22, C24, C25) |
| GCP `c3` Confidential VM, Intel TDX | `gcp-tdx` | `gcp-tdx/returnpath-e2e` (C15); a TDX authority with its escrow key in the vTPM (C23) |
| Azure NCC H100 v5, AMD SEV-SNP (Genoa) + the confidential H100 | `azure-cgpu` | `azure-cgpu` (C17, C20, C26), `failover-cgpu` (C18) |

A daemon on a Linux confidential VM need not name its hardware:
`tee.provider: "auto"` reads which family the kernel's configfs-tsm
serves (`sev_guest` or `tdx_guest`) when the configuration is loaded and
runs as that family — its identity, its logs and its audit records name
the family, and the start log names the kernel's answer. The family
names `sev-snp` and `tdx` are accepted beside the names above (ADR 0025).
The peer's provider is still named: a pin says what the other side must
be.

A simulated TEE runs anywhere and is for development: both daemons refuse
to start with it unless the config says `tee.provider: "simulated"` with
`tee.insecure_simulation: true`, and a first deployment on real hardware
sets neither. AWS Nitro and Intel SGX are measured by their kits
(`scripts/hardware-test/aws-nitro`, `azure-sgx`) and refused by the
daemons' verifier registry; an Azure SEV-SNP Confidential VM without a GPU
is measured by `azure-sev-snp` and is not a provider yet.

The worker host needs Python 3.12 and the worker package from the release
(`genome-worker-<tag>.tar.gz`: `vg_genome`, its locks and examples), with
the runtime from the hash-pinned locks inside it — `requirements-ci.lock` from PyPI,
then the torch wheel for the host from the PyTorch index that carries it
(`requirements-torch-cpu.lock`; a GPU host adds the CUDA libraries and the
cu126 wheel from their own locks), each lock from its own index with
`pip --require-hashes --only-binary=:all:` — and the public base model the
genome names, at the pinned revision, on local disk. The reference guest
installed the runtime in 84 s (`results/timeline.txt`); on a fresh image
that step is the package mirror's to decide, which is why a standby that
matters keeps its runtime installed.

## 3. Prepare the host

In the order the reference guest script does it
(`scripts/hardware-test/gcp-sev-snp/returnpath-e2e/cvm-returnpath.sh`):

1. **The chip is reachable.** On SEV-SNP, `configfs-tsm` is mounted and
   `/dev/sev-guest` exists; on TDX, `/dev/tdx_guest`; on the Azure host, the
   vTPM's HCL report at NV index `0x1400001`. The real-TEE runbooks
   ([SEV-SNP](runbooks/real-tee-sev-snp.md), [TDX](runbooks/real-tee-tdx.md),
   [Azure cGPU](runbooks/real-tee-azure-cgpu.md)) show the report chained
   to the vendor's root before anything else is trusted.
2. **Provision the key material** with the release's `acp-keygen`
   (`acp-keygen -out <dir> -private`; stdlib-only, signed and attested like
   the daemons): the private CA and the two TLS identities, the session
   sealing key, the signing seeds, the REST token, the worker registry
   (`deploy/compose/README.md` lists every file). The AMD chain the
   verifiers need comes from `acpctl tee fetch-amd-chain --product
   <milan|genoa|turin> --out <file>`, which verifies it against the roots
   the binary pins before writing it (ADR 0024). A host that will lose its
   route to the vendors fills its verifiers' caches now — `acpctl tee
   prefetch --config <daemon config>` for each daemon, `acpctl tee
   cache-status` for what is there and until when
   ([runbooks/air_gap.md](runbooks/air_gap.md)). Then seal the key files
   in place on the host — `sagvd seal-keys`, `acp-compute
   seal-keys` (ADR 0023): each file is sealed to the chip's derived key on
   SEV-SNP, to the vTPM on TDX and on the Azure host, and opened at start;
   `tee.sealer` chooses — `auto` takes the TEE's own key where there is
   one and the TPM 2.0 otherwise, `tpm2` takes the host's TPM on any
   hardware — and every sealed file names the sealer it was made with
   (ADR 0025, step 1b).
   A plaintext escrow key is refused on a hardware TEE; `sagvd
   escrow-provision` makes it sealed (ADR 0016).
3. **Identities and pins.** `sagvd identity -config sagvd.json` and
   `acp-compute identity -config worker.json` read each daemon's launch
   measurement from the chip; each goes into the other's
   `tee.peer.measurement_path`, with the vendor chain the provider needs
   (the AMD chain for the chip's product line, Intel's PCS cache, NVIDIA's
   key set). `sagvd identity` also prints the audit public key
   (`audit_public_key_pem`): keep it off the host — it is what an auditor
   verifies the log with.
4. **A genome to gate.** Seal one with `acpctl genome seal --content-dir
   <genome> --output <bundle> --key-out <key file>`; the key file is `0600`
   and never on a command line. The reference sealed a tiny fine-tune made
   on the guest (10 s); a real model's genome seals the same way (C1–C4).

## 4. Start it, and prove it the way the reference did

1. **`sagvd`** with its config: the Return Path on `vault.listen_address`
   under mutual TLS 1.3 (`vault.tls`), the REST API with its bearer token
   (`http_api.bearer_token_file`), the health listener, `genome.bundle_dir`,
   `audit.log_path`, and `queue.path` for the job store a restart resumes
   from (ADR 0026). Off loopback it refuses to start with either listener
   unauthenticated ([01](01_preflight.md) §8). `GET /readyz` answers once
   it is up.
2. **The refusal first.** Before the real worker, the reference starts a
   worker that is *not* the pinned identity — the same certificate and
   sealing key, a simulated TEE in place of the chip — and expects it
   refused at the Return Path handshake with the refusal on the record
   (`results/rogue-worker.log`: refused after 1 s; `sagvd return-path
   handshake failed` in the log). A first deployment can do the same; it
   costs a minute and proves the pins are live.
3. **`acp-compute`** with its config: `vault.address`, its client
   certificate, `genome.door.command` naming the `vg_genome` door with
   `--base <base model dir>` and the device. The handshake succeeds when
   both pins match (`sagvd` logs the admission; `TRUST_EVALUATED` on the
   audit record).
4. **A gate job** over the REST API:

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     --data '{"genome":{"bundle":"gen-0.genome","key_file":"gen-0.key"},"deadline_seconds_from_now":300}' \
     http://127.0.0.1:9080/v1/jobs
   curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9080/v1/jobs/<id>
   ```

   The reference's `results/job.json`: `status: succeeded`, decision
   `release_authorized`, gate **EXACT** at rung 0, 6 of 6 fixtures,
   `max_abs_err` 0, the verdict signed by the authority's key; 5.2 s from
   submission to the sealed audit event. A genome of a real model on the
   pinned runtime gates EXACT (C4); across hardware it gates EQUIVALENT and
   the verdict says which (C5, [KNOWN_ISSUES.md](../../KNOWN_ISSUES.md) #13).
5. **The record.** Stop both daemons and verify the log with the key from
   step 3.3:

   ```bash
   acpctl audit verify --audit <audit.log_path> --audit-pubkey audit.pem --audit-kid <keys.audit_signing.kid> --json
   acpctl audit query --audit <audit.log_path> --limit 0 --json
   ```

   The reference: `ok: true`, 17 events from the first start to the sealed
   verdict, every decision in order (`results/audit-verify.json`,
   `results/audit-events.jsonl`). A log that does not verify stops every
   release ([03](03_incident_response.md), [04](04_observability.md) §2).

## 5. What to keep, and what comes next

Keep, off the host: the release's hashes and your verification output
(§1), the audit public key, the two measurements, the verified audit log's
tip. They are what the next person compares with.

Then: the preflight checklist monthly ([01](01_preflight.md)); the metrics
and the audit chain in your monitoring ([04](04_observability.md)); the
failover policy and its drill before you rely on it
([07](07_failover.md), `docs/CONTINUITY-DRILL.md`); a cross-cloud destination
when a second cloud is wanted ([06](06_cross_cloud_restore.md)); the next
release along [08](08_upgrading.md), verified as in §1 before it runs.

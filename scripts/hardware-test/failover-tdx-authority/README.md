# The TDX-authority drill: the release authority on an Intel TDX Trust Domain, its escrow key in the vTPM

The TDX drill ([failover-tdx](../failover-tdx)) put the *standby* on Intel
TDX; this one puts the **release authority** there. TDX gives a guest no
sealing key of its own, so `sagvd`'s escrow key — made inside its process
— is sealed to the guest's vTPM under a policy only this boot's PCRs
satisfy ([ADR 0022](../../../docs/adr/0022-the-escrow-key-sealed-to-the-vtpm.md)),
opened once to prove it, and re-sealed through the operator's recovery
ceremony. Then the drill runs as before: a SEV-SNP primary is attacked,
and the authority on TDX releases the last trustworthy genome's key to a
TDX standby across the VPC.

```bash
bash scripts/hardware-test/failover-tdx-authority/run.sh <gcp-project> [n2d-zone] [tdx-zone]
```

`run.sh` builds `sagvd`, `acp-bootstrap`, `acpctl` and `keygen` for
linux/amd64, packs `workers/genome`, and boots three Confidential VMs in
one project:

- The **authority** ([`authority-tdx.sh`](authority-tdx.sh)) —
  `c3-standard-4`, Intel TDX, tpm2-tools on the guest's vTPM: `sagvd
  escrow-provision` seals the escrow key to the vTPM (`tee.provider:
  "gcp-tdx"`), the recovery ceremony re-seals it, `sagvd failover` unseals
  it at start and attests as `gcp-tdx`; the registry holds the `gcp-tdx`
  destination and the primary's `gcp-sev-snp` anchors; the policy pins
  the primary's chip and the standby's measurement.
- The **primary** ([`../gcp-failover/primary.sh`](../gcp-failover/primary.sh),
  unchanged) — `n2d-standard-8`, SEV-SNP.
- The **standby** ([`../failover-tdx/destination-tdx.sh`](../failover-tdx/destination-tdx.sh),
  unchanged) — `c3-standard-4`, Intel TDX, `acp-bootstrap` as `gcp-tdx`.

Every hand-off goes through the private bucket; every VM and the bucket
are deleted on exit, on success or failure.

## Results — run `20260916T200841Z`

Three live confidential machines in one GCP project: the authority a
`c3-standard-4` Intel TDX Trust Domain (us-central1-a), the primary an
`n2d-standard-8` AMD SEV-SNP VM (europe-west4-a), the standby a
`c3-standard-4` Trust Domain; the model of the failover drill
(Qwen2.5-0.5B-Instruct, LoRA r8, float32 on the primary's CPUs).

**The authority's vTPM** (`authority/vtpm.txt`, `vtpm-pcrs.txt`):
`/dev/tpm0` and `/dev/tpmrm0` on the Trust Domain, `[    2.147722] tpm_tis MSFT0101:00: 2.0 TPM (device-id 0x9009, rev-id 0)`;
the fifteen PCRs of this boot as read before the key was sealed.

**The escrow key, sealed to the vTPM** (`authority/escrow-provision.json`,
`escrow-sealed-shape.txt`, `authority-identity.json`): `sagvd
escrow-provision` on `tee.provider: "gcp-tdx"` exit 0, key `221addd3bffe3f79`,
`tee: gcp-tdx`, sealed at the Trust Domain's measurement `ed70198a…177b`
and opened once on the spot to prove it; the file on disk is
`{'tee': 'gcp-tdx', 'schema': 'vault-genome/vtpm-sealed/v1', 'pcrs': 'sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14', 'public_bytes': 80, 'private_bytes': 160, 'box_bytes': 60}` — the vTPM's sealed object and the AES-GCM box, no key bytes.
`sagvd identity`: `key_escrow_storage: sealed:gcp-tdx`. **The recovery
ceremony on TDX** (`escrow-reprovision.json`): the operator's envelope
opened with the recovery key and the same key `221addd3bffe3f79` re-sealed to
this vTPM (`source: stdin`).

**The failover** (`authority/report.json`, `failover.log`,
`destination/acp-bootstrap.log`, `*.receipt.json`): `sagvd failover`
unsealed the escrow key from the vTPM at start and attested as `gcp-tdx`;
the policy (serial 1) pinned the primary's chip `69da361d…c790` and the standby's
measurement `ed70198a…177b`; the primary was attacked and reported at
20:19:49.37Z; the authority decided *restore generation 1*, verified
the standby's TDX quote to Intel's root with Intel's TCB word, released
the key (`destination_kind: gcp-tdx`, `policy_version: failover-policy-v1;failover=1;revocation=1`)
and confirmed the receipt.

| Phase | Measured |
| - | - |
| Detect — tripwire → authority observes | **7.73 s** |
| **RPO** — data at risk | **12.00 s** |
| Key release — across the VPC, mTLS | 0.52 s |
| Restore — 5 files, 2,210,917 B | **11.0 ms** |
| Gate on the standby's CPUs | 10.78 s |
| Failover — trigger observed → confirmed | 12.54 s |
| **RTO** | **20.27 s** |

Generation 1 came back **EQUIVALENT** (16 fixtures, `max_abs_err: 1.45e-4`) — sealed on
AMD Milan cores, proven on Intel Sapphire Rapids cores, as in the TDX
drill. Audit chain of 5 events, `audit-verify.json`: `ok: true`, tip
`78551451…bb2f`.

**What is new here is the authority.** The machine that held the key that
moves the model is a Trust Domain, and the key it held was sealed to
hardware it runs on — the guest's vTPM under a policy of this boot's PCRs
— not to a file. ADR 0022 says what that root is and is not.

**Cost.** About 15 minutes on the three machines, cents.

## Evidence files

- `authority/` — the TDX drill's authority files (`escrow-provision.json`,
  `authority-identity.json`, `identity-0.err`, `destination-handoff.json`,
  `primary-identity.json`, `verifiers.json`, `allow.json`,
  `failover-issue.txt`, `failover-verify.txt`, `failover-policy.json`,
  `report.json`, `failover.log`, `audit-events.jsonl`,
  `audit-verify.json`, `cache-vcek-*.der`, `cache-pcs-tdx-*`,
  `timeline.txt`, `metadata.txt`, `system.txt`, `tsm.txt`, `steps.txt`,
  `console.log`) and the vTPM's: `vtpm.txt`, `vtpm-pcrs.txt`,
  `escrow-sealed-shape.txt`, `escrow-reprovision.json`,
  `escrow-recover.err`, `escrow-reprovision.err`, `recovery-keygen.txt`.
- `primary/`, `destination/` — as in the TDX drill.

The evidence holds no key, seed, token or config: the sealed escrow key's
bytes and the recovery seed are not in it (the sealed file's shape is),
the bearer token and the TLS material crossed only through the run's
private bucket, and the bucket was deleted with the VMs.

## Scope

One run, the 0.5B model, one TDX authority. The sealing rests on the
guest's vTPM — a device Google virtualises inside the Trust Domain — and
on a PCR policy of this boot; the TEE's own attestation is still Intel's.
An operator who does not accept the provider's vTPM as a root has no
sealed escrow key on a TDX host. The same sealer on an Azure confidential
GPU host is proven in [azure-cgpu](../azure-cgpu) (run `20260916T204311Z-returnpath`: sealed, opened, re-sealed through the ceremony).

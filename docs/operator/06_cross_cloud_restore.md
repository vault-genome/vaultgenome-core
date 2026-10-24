# Operator Runbook 06 — Cross-Cloud Key Release and Genome Restore

**Design:** [ADR 0006](../adr/0006-cross-cloud-kms-mediated-restore.md) (flow, audit kinds),
[ADR 0009](../adr/0009-x25519-kem-cross-cloud-key-delivery.md) (how keys travel),
[ADR 0010](../adr/0010-operator-stop-and-recorded-refusals.md) (the operator stop) and
[ADR 0011](../adr/0011-genome-v3-and-attested-self-restore.md) (sealed genomes, restore, receipts).
**Proven by:** `test/integration/crosscloud_test.go` and `genome_drill_test.go`, which run every
step below with the real binaries.

---

## What this runbook covers

Bringing a sealed genome up on another machine or cloud: the **source
authority** (`sagvd`) releases the genome's key to a **destination**
(`acp-bootstrap`) only after the destination proves — by remote attestation —
that it is a genuine TEE running a workload the operator allow-listed; the
destination then restores the genome by itself and signs a receipt; the source
verifies that receipt and records the restore.

What the shipping binaries do today, stated exactly:

- `acp-bootstrap` attests with **AMD SEV-SNP** (`tee.provider: "gcp-sev-snp"`,
  reports through the kernel's configfs-tsm on a Confidential VM), with
  **Intel TDX** (`"gcp-tdx"`, a quote through the same interface, ADR 0018)
  or with the **simulated** backend, whose Evidence is signed by a key
  derived from a seed file — that proves the protocol, not hardware
  isolation. The examples below use the simulator so they run anywhere; the
  SEV-SNP settings are in
  [runbooks/real-tee-sev-snp.md](runbooks/real-tee-sev-snp.md) §D, the TDX
  settings in [runbooks/real-tee-tdx.md](runbooks/real-tee-tdx.md). `sagvd`'s
  verifier registry accepts `simulated`, `gcp-sev-snp`, `gcp-tdx` and
  `azure-cgpu` (an Azure confidential GPU VM, ADR 0019, settings in
  [runbooks/real-tee-azure-cgpu.md](runbooks/real-tee-azure-cgpu.md)) and
  refuses every other family until its verifier runs end to end. A key
  release to a TDX or confidential-GPU destination has not been run on
  hardware yet; the Return Path on both has.
- Genomes are sealed with `acpctl genome seal` into v3 bundles whose key is
  in a separate 0600 file. Bundles are opaque without their keys, so they can
  be replicated to the destination ahead of any release. With a `genome`
  section, `acp-bootstrap` restores a bundle as soon as its key arrives, and
  wipes the key from memory once the restore is signed for.

## How a key travels

```
 source: sagvd crosscloud-restore                    destination: acp-bootstrap
 ────────────────────────────────                    ───────────
 signed handshake, fresh nonce N,  ── TLS 1.3 ──▶    verify authority signature
 the KEM suites it accepts                           pick the first suite it accepts,
                                                     new key pair (sk, pk) under it
                                   ◀── Evidence ──   quote over C = H(label ‖ suite ‖ pk ‖ N)
 the suite is on its list?                           (sk stays in memory, 5 min,
 verify Evidence under C                              one token)
 (genuine TEE + measurement +
  freshness + suite and pk are the TEE's own)
 allow-list policy on measurement
 encapsulate DEKs to pk under the suite
 signed key-release token          ── TLS 1.3 ──▶    take sk (single use), open DEKs
 (each key names its suite)                          under the handshake's suite,
                                                     register, zeroize sk
```

A destination that presents no attested key, one that answers under a suite
the source does not accept, an Evidence that does not verify for the
presented suite and key, or a measurement that is not on the allow-list gets
no token. There is no fallback path, and no negotiation below either side's
list.

### The cryptographic profile

Which KEM suites the two sides use is the `crypto` section of each daemon's
configuration (ADR 0029). `crypto.profile` is one of:

| Profile | The daemon writes | It accepts |
| - | - | - |
| `general` (default) | `hpke-x25519-v2` | every suite of the build: X25519, P-384, ML-KEM-768, the MLKEM1024-P384 hybrid, X-Wing |
| `fips` | `hpke-p384-v2` | `hpke-p384-v2`, `hpke-mlkem768-v2`, `hpke-mlkem1024-p384-v2` — the primitives the Go Cryptographic Module (CMVP #5247) lists as approved |
| `cnsa` | `hpke-mlkem1024-p384-v2` | that hybrid only |

The suites are the v2 ones of ADR 0030: HPKE opened export-only derives
the key, and the cryptographic module's AES-256-GCM seals under it with
the nonce it generates. The v1 suites of 0.7.0 (the AEAD inside HPKE)
still open on a build without enforcement; nothing writes them, and a
0.7.0 peer and a 0.8 peer release nothing to each other.
`crypto.kem_suites` narrows a profile's list to the suites named, in that
order of preference (the first is written); it never widens one. The source
offers its list in the handshake, the destination takes the first entry its
own list accepts, and both record the result: `recipient_key_suite` in the
destination's log and in the source's report, `delivery_mode` and
`crypto_profile` in the audit chain. A `fips` source and a `general`
destination meet on P-384; a `cnsa` source and a `fips` destination on the
hybrid; a source that offers nothing the destination accepts is refused at
the handshake, on the source's record. Both daemons must run a release that
knows suites: a request or an answer that names none is refused.

The same profile decides the signature suite (ADR 0031) — what the
authority signs its verdicts, tokens, manifests and audit events with,
and what a destination accepts them under:

| Profile | The daemon signs with | It accepts |
| - | - | - |
| `general` (default) | `ed25519` | `ed25519`, `ecdsa-p384-sha384`, `ml-dsa-87` |
| `fips` | `ed25519` | `ed25519`, `ecdsa-p384-sha384` — the two on the certificate of the Go Cryptographic Module v1.0.0 |
| `cnsa` | `ecdsa-p384-sha384` | `ecdsa-p384-sha384`, `ml-dsa-87` |

`crypto.signature_suite` picks the signing suite within the profile's
list and never widens it — `fips` with `ecdsa-p384-sha384` is the
deployment a bank held to X9 SD-34 runs. The keys must be of that suite:
`acp-keygen -signature-suite` makes them, `keys.<name>.suite` in each
config names the suite the key file is read under (the 32-byte seed of
an `ed25519` or `ml-dsa-87` key, the PKCS#8 PEM of an
`ecdsa-p384-sha384` key; `ed25519` when absent), and a key of another
suite than the profile signs with stops the daemon at startup with the
reason. A key the profile does not accept is refused where it is pinned,
with the reason: a worker registry entry, the operator's stop key, the
sentinel key a failover policy pins, the source authority key the
destination pins. Every record names its suite (`alg`, absent for
`ed25519`), `identity` prints `signature_suite` and `signature_suites`
beside the KEM suites and the suite of each key beside its PEM, and
`acpctl audit verify` reports the suite of the key the chain verified
under. `ml-dsa-87` is the standard library's: on the `-fips` build it is
refused with the module's reason.

Both daemons' `identity` and every command's `version` also report
`fips140` — whether the build runs the certified Go Cryptographic Module
(`enabled`), whether enforcement is on (`enforced`, the `fips140=only`
assessment mode, never a production setting), the module version and
the build setting (ADR 0030). Under enforcement a configuration that
names `general` is refused at startup, because its first suite is
X25519, which the module cannot make, and a configuration that names no
profile runs as `fips`; a deployment assessed that way names `fips` or
`cnsa`.

---

## Pre-flight: exchange identities

Each side prints what the other pins. Neither command opens a listener.

**Source** — the authority key every destination verifies handshakes and tokens against:

```bash
sagvd identity -config /etc/acp/sagvd.json > authority.json
jq -r .authority_public_key_pem authority.json > authority.pem   # give to the destination
jq -r .authority_kid authority.json                               # the kid the destination pins
```

**Destination** — the TEE family, measurement and (simulated backend) attestation key:

```bash
acp-bootstrap identity -config /etc/acp/acp-bootstrap.json > destination.json
jq -r .attestor_public_key_pem destination.json > destination-attestor.pem   # give to the source
jq -r .measurement_hex destination.json                                      # goes on the allow-list
acp-bootstrap seal-keys -config /etc/acp/acp-bootstrap.json                  # on a hardware TEE: the TLS key and the token sealed in place (ADR 0023)
```

Compare the SHA-256 of each file over a second channel before pinning it.

## Destination configuration (`acp-bootstrap`)

```json
{
  "crypto": { "profile": "general" },
  "http": {
    "listen_address": "0.0.0.0:8443",
    "bearer_token_file": "/etc/acp/secrets/acp-bootstrap/api_token",
    "tls": {
      "enabled": true,
      "server_cert": "/etc/acp/secrets/acp-bootstrap/tls/server.crt",
      "server_key": "/etc/acp/secrets/acp-bootstrap/tls/server.key",
      "client_cas": "/etc/acp/secrets/shared/tls/ca.crt"
    }
  },
  "tee": {
    "provider": "simulated",
    "insecure_simulation": true,
    "workload_descriptor": "acp-bootstrap-destination-v1",
    "seed_path": "/etc/acp/secrets/acp-bootstrap/tee_seed"
  },
  "source_authority": {
    "kid": "sagvd-authority-demo",
    "public_key_path": "/etc/acp/authority.pem"
  },
  "genome": {
    "bundle_dir": "/var/lib/acp/bundles",
    "restore_dir": "/var/lib/acp/restored"
  },
  "health": { "listen_address": "127.0.0.1:8444" },
  "log": { "level": "info", "format": "json" }
}
```

Exposure rules are enforced at startup; a config that breaks one does not start:

- Beyond a loopback address the listener must use TLS. It speaks **TLS 1.3 only**.
- Beyond loopback, callers must present a client certificate (`client_cas`) or a
  bearer token of at least 32 characters (`bearer_token_file`, or inline
  `bearer_token`); configure both for defence in depth.
- The simulated provider runs only with `insecure_simulation: true`: its
  "Evidence" is signed by a key read from `seed_path`, a 32-byte file, so it has
  no hardware isolation and is for development and tests. With `gcp-sev-snp`
  the chip signs and neither field applies. `public_key_path` accepts the PEM
  printed by `sagvd identity` or the raw 32 bytes.
- `tee.provider` is also the only `destination_tee_kind` the daemon answers; a
  handshake declaring another kind is refused.
- `genome` (optional): `bundle_dir` holds sealed bundles waiting for their keys;
  each restored genome lands in `restore_dir/<key id>/`, its signed receipt in
  `restore_dir/<key id>.receipt.json`. Both are absolute and separate. Copy
  bundles in under another name and rename them to `*.genome`, so a
  half-written bundle is never picked up. A key that arrives before its bundle
  waits for it (`rescan_seconds`, default 5). Where nobody else can write into
  `bundle_dir` — inside a Nitro enclave, which has no disk of its own — the
  source posts the sealed bundle to `POST /v1/genome/bundles` over the same
  authenticated API (ADR 0036): at most `max_bundle_bytes` (default 1 GiB; a
  large bundle also needs `http.write_timeout_seconds` long enough), refused
  unless its header is a v3 bundle's, stored as `<sha256>.genome` by a rename,
  and refused if another bundle for the same key is already there; the same
  bytes again are answered as already there. The bundle is ciphertext without
  its key, and the receipt names its digest, which the source checks.
- `http.listen_vsock_port` (instead of `listen_address`) serves the API on an
  AF_VSOCK port — the only channel into a Nitro enclave, which has no network
  interface at all (ADR 0036). The parent instance forwards bytes to the port
  and sees ciphertext: TLS terminates in the daemon, and a vsock listener is
  held to the rules of a non-loopback address (TLS, and mTLS or a bearer token
  of at least 32 characters).
- `genome.gate` (optional) proves a restored model works before the receipt is
  signed. `command` runs the gate backend — the `vg_genome` door
  (`workers/genome`), with `{genome}` standing for the restored directory — which
  recomputes the genome's sealed fixtures on this machine; the equivalence gate
  holds them to their references, byte-exact first, then within `atol`/`rtol`.
  The verdict (EXACT, EQUIVALENT or FAIL) goes into the receipt. With
  `required: true` a genome that cannot be gated (no model fixtures, a backend
  that does not run) fails its restore instead of being signed for without a
  verdict:

  ```json
  "gate": {
    "command": ["python3", "-m", "vg_genome", "door", "--genome", "{genome}",
                "--base", "/var/lib/acp/base/qwen2.5-0.5b-instruct", "--device", "cuda"],
    "env": ["PYTHONPATH=/opt/vaultgenome/workers/genome"],
    "atol": 0.01, "rtol": 0.001, "required": true
  }
  ```

  The base model directory must hash to the genome's manifest; the door refuses
  any other.

The health listener answers `/healthz` and `/readyz` and exposes nothing else.

### A Nitro enclave as the destination

An enclave has no disk, no network and, in production mode, no console
anyone can read; `acp-bootstrap` runs inside it from an image the operator
builds, and the parent instance forwards bytes (ADR 0036). The
configuration is in the image, under PCR0:

```json
"http": {
  "listen_vsock_port": 5000,
  "bearer_token_file": "/run/vg/keys/token",
  "tls": { "enabled": true, "server_cert": "/etc/vg/tls/server.crt",
           "server_key": "/run/vg/keys/server.key", "client_cas": "/etc/vg/tls/ca.crt" }
},
"tee": {
  "provider": "aws-nitro",
  "workload_descriptor": "acp-bootstrap-destination-v1",
  "secret_files_vsock_port": 7000,
  "aws_kms": { "key_arn": "arn:aws:kms:us-east-2:<account>:key/<id>",
               "kms_vsock_port": 8000, "imds_vsock_port": 8002 }
},
"source_authority": { "kid": "sagvd-authority", "public_key_path": "/etc/vg/authority.pem" },
"genome": { "bundle_dir": "/run/vg/bundles", "restore_dir": "/run/vg/restored" },
"health": { "listen_address": "" },
"log": { "level": "info", "format": "json", "vsock_port": 7001 }
```

- What is not secret goes into the image — the daemon, this file, the
  source authority's public key, the TLS certificate and the CA — so PCR0
  covers it. The key files (the TLS server key, the bearer token) do not:
  they are sealed for the image's PCR0 on the operator's machine,
  `acp-bootstrap seal-keys -config <this file> -pcr0 <PCR0 from nitro-cli
  describe-eif> -root <the staged files>`, under the operator's AWS
  credentials, with a KMS key whose policy allows `kms:Decrypt` to the
  parent's role only when `kms:RecipientAttestation:ImageSha384` is that
  PCR0 and denies it to every principal without an attestation document
  (`key_policy` in `scripts/hardware-test/aws-nitro/crosscloud-e2e/run.sh`
  is the reference). At start the parent hands the sealed files to the
  enclave on `tee.secret_files_vsock_port` as `{"files": {"<path>":
  "<base64>"}}` — exactly the paths this file names, nothing else, or the
  enclave refuses them all — and the enclave opens them through KMS with
  its own attestation document.
- The parent runs four forwarders and reads none of the bytes: the
  source's TLS from a TCP port to `http.listen_vsock_port`; the enclave's
  TLS to `kms.<region>.amazonaws.com:443` on `kms_vsock_port`; its HTTP to
  the instance metadata service on `imds_vsock_port`; the log on
  `log.vsock_port`. `scripts/hardware-test/aws-nitro/crosscloud-e2e/parent`
  is the reference. None of these may be port 9000, where nitro-cli takes
  the enclave's boot heartbeat.
- `health.listen_address` must be empty: the enclave has no loopback. The
  restored genome lives in the enclave's memory (`/run`); give the enclave
  memory for the bundle, the restore and the daemon.
- `acp-bootstrap identity` cannot run outside an enclave; the measurement
  the source pins is the image's PCR0 as `nitro-cli describe-eif` prints
  it. The source's registry entry names it and may pin more:

  ```json
  { "provider": "aws-nitro",
    "expected_measurement_hex": "<PCR0>",
    "nitro": { "pcrs": { "1": "<PCR1>", "2": "<PCR2>" }, "max_clock_skew_seconds": 300 } }
  ```

  Pin PCR1 and PCR2 (the kernel and the application, both printed by
  `describe-eif`) and PCR8 when the image is signed. PCR3 and PCR4 (the
  parent's IAM role and instance) narrow further and never stand in for
  PCR0: a debug-mode enclave keeps them, and the source refuses a
  debug-mode document whatever the pins say. The AWS Nitro Enclaves root
  is the binary's own; nothing in the entry names a certificate.

## Source configuration (`sagvd`)

Add a `crosscloud` section, and the audit signing key, to the usual `sagvd`
config:

```json
"keys": {
  "audit_signing": { "kid": "sagvd-audit", "seed_path": "/etc/acp/secrets/sagvd/audit_signing_seed" },
  "…": "authority_signing, session_sealing as before"
},
"crypto": { "profile": "general" },
"crosscloud": {
  "enabled": true,
  "audit_log_path": "/var/lib/acp/xcc-audit.db",
  "policy_version": "xcc-2026-09-14",
  "policy_allow_list_path": "/etc/acp/crosscloud/allow.json",
  "verifier_registry_path": "/etc/acp/crosscloud/verifiers.json",
  "operator_stop": {
    "kid": "operator-1",
    "public_key_path": "/etc/acp/crosscloud/operator.pem",
    "list_path": "/etc/acp/crosscloud/stop.json"
  },
  "key_escrow_path": "/etc/acp/secrets/sagvd/escrow.sealed",
  "transport_bearer_token": "<the destination's bearer token>",
  "request_timeout_seconds": 30,
  "transport_tls": {
    "enabled": true,
    "client_cert": "/etc/acp/secrets/sagvd/tls/client.crt",
    "client_key": "/etc/acp/secrets/sagvd/tls/client.key",
    "ca_bundle": "/etc/acp/secrets/shared/tls/ca.crt"
  }
}
```

`operator_stop` points at the operator's signed stop list and is required.
`key_escrow_path` is needed only to release escrowed genome keys (`-key-escrow`);
it names the sealed key `sagvd escrow-provision` wrote (see [Sealing a
genome](#sealing-a-genome) above).
To release to a simulated destination in development, add
`"insecure_simulated_destinations": true`; without it a simulated entry in the
verifier registry is refused.

No key is released without a durable record: `audit_log_path` and
`keys.audit_signing` are required. Every release writes its handshake,
attestation and authorisation events to that log, signed and hash-linked,
before the step each one records. The log is verified end to end whenever
`crosscloud-restore` opens it; a log that does not verify stops all releases.
One run holds its lock at a time. The audit seed must stay the same for the
life of the log (`sagvd identity` prints its public key for auditors).

`insecure_simulated_destinations` lets the verifier registry hold a
`simulated` entry — needed for the simulated examples here, and never for a
hardware destination. Without it a simulated entry stops `sagvd` before any
handshake. (`sagvd`'s own `tee` section likewise requires
`insecure_simulation: true`: this build's authority attests with the simulator
only; the cross-cloud release path does not depend on it.)

`verifiers.json` — how to check each destination family's Evidence:

```json
{ "verifiers": [ {
  "provider": "simulated",
  "attestor_pubkey_path": "/etc/acp/crosscloud/destination-attestor.pem",
  "expected_measurement_hex": "<measurement_hex from acp-bootstrap identity>"
} ] }
```

`allow.json` — the operator's release policy. Its `version` must equal
`policy_version`, or `sagvd` refuses to load it:

```json
{ "version": "xcc-2026-09-14",
  "allowed": { "simulated": ["<measurement_hex from acp-bootstrap identity>"] } }
```

Measurements are pinned whole: 32, 48 (SEV-SNP, Nitro) or 64 bytes.

## Sealing a genome

On the machine that holds the model or the fine-tune output:

```bash
acpctl genome seal --content-dir=./adapter --output=gen-1.genome --key-out=gen-1.key --json > seal.json
```

The report names the bundle's `key_id` (`genome-<payload>-g<generation>-<key
tag>`). `gen-1.key` holds the 32-byte key, mode 0600, and is never overwritten;
keep it with the release authority. Replicate `gen-1.genome` to the
destination's `bundle_dir` (see above).

**Or keep no key on the sealing machine at all (key escrow).** The release
host makes its escrow key inside its own process and writes it only sealed to
its TEE ([ADR 0016](../adr/0016-escrow-key-sealed-to-the-release-host.md)):
on SEV-SNP under a key the chip derives for that guest, launch measurement
and policy, which the daemon unseals in memory at start. Set
`crosscloud.key_escrow_path` to the sealed file; `sagvd identity` then prints
the public half as `key_escrow_public_key_pem` and says how the private half
is kept (`key_escrow_storage: sealed:gcp-sev-snp`):

```bash
# On the operator's machine, once: the recovery key. Its private half never goes to the release host.
# --suite names its KEM suite (ADR 0029): the one your profile writes, here P-384 for a fips deployment.
acpctl escrow recovery-keygen --suite hpke-p384-v2 --out recovery.seed --pub recovery.pem
# On the release host: the escrow key, made under the suite crypto.profile writes (or -suite),
# sealed to this host, wrapped to the recovery key.
sagvd escrow-provision -config /etc/acp/sagvd.json -out /etc/acp/secrets/sagvd/escrow.sealed -pub escrow.pem \
  -recovery-to recovery.pem -recovery-out /etc/acp/secrets/sagvd/escrow.recovery
# On the sealing machine:
acpctl genome seal --content-dir=./adapter --output=gen-1.genome --escrow-to=escrow.pem --json > seal.json
```

The sealer encapsulates the fresh key to the escrow key — RFC 9180 HPKE under
the key's suite, which `escrow.pem` names: PKIX for an X25519 or P-384 key,
the product's own `VAULT GENOME HPKE PUBLIC KEY` block for an ML-KEM or
hybrid key — in `gen-1.genome.escrow` and writes no key file. The envelope
names the suite and travels with the bundle; it opens only on the release
host, which releases the key with `-key-escrow gen-1.genome.escrow` instead of
`-key-file`. `sagvd identity` prints the escrow key's tag, its PEM and its
suite (`key_escrow_suite`). Envelopes, sealed keys and recovery envelopes of
releases before 0.7 (the X25519 KEM of ADR 0009) still open with the same
X25519 key.

The sealed key opens only on the same chip at the same launch measurement
and guest policy, and — on a Compute Engine SEV-SNP host sealed with
`tee.sealer: both`, the default of `gcp-sev-snp-vtpm` (ADR 0037) — on the
boot its vTPM policy names. A restart that lands on another host, a new image
or kernel on such a host, a dead chip: `sagvd` refuses to start and says
which measurement the key was sealed at. Keep `escrow.recovery` (ciphertext, useless without `recovery.seed`) where
a restart can reach it, and re-seal on the new host through a pipe, so its disk
never holds the key in the clear:

```bash
acpctl escrow recover --in escrow.recovery --key recovery.seed \
  | ssh release-host sagvd escrow-provision -config /etc/acp/sagvd.json -out /etc/acp/secrets/sagvd/escrow.sealed -pub escrow.pem -stdin
```

The same key, the same tag, the same suite; sealers pinned to `escrow.pem`
need no change. What crosses the pipe is a PEM naming the key's suite; the
new host's profile must accept that suite.
Under `tee.insecure_simulation` a plaintext key from `acpctl escrow keygen`
is still accepted, for development and tests, and the daemon logs
`PLAINTEXT ESCROW KEY`; on a hardware TEE it is refused.

## Releasing keys

```bash
sagvd crosscloud-restore \
  -config /etc/acp/sagvd.json \
  -decision-id dec-2026-09-14-001 \
  -destination-kind simulated \
  -destination-endpoint https://destination.example.com:8443 \
  -key-file "$(jq -r .key_id seal.json):/etc/acp/keys/gen-1.key"
```

`-key-file KID:PATH` and `-key-escrow ENVELOPE` repeat for several keys. Keys
are read from files only —
a key on a command line would sit in process listings and shell history — and a
key file other users can read is refused. For a genome key ID the key must match
the tag the ID carries, so a wrong key file is caught before anything moves. The
endpoint must be `https`, except to a loopback destination. The command prints
one JSON report and exits 0 on success, 1 on any refusal:

```json
{
  "status": "ok",
  "handshake_request_id": "…",
  "handshake_audit_id": "…",
  "attestation_audit_id": "…",
  "key_release_audit_id": "…",
  "destination_measurement_hex": "…",
  "recipient_key_sha256": "…",
  "recipient_key_suite": "hpke-x25519-v2",
  "crypto_profile": "general",
  "policy_version": "xcc-2026-09-14",
  "token_id": "…",
  "dispatched_at": "2026-09-14T12:00:00.000Z",
  "audit_chain_length": 3,
  "audit_tip": "…"
}
```

The `CROSS_CLOUD_ATTESTATION_VERIFIED` event behind `attestation_audit_id`
names the destination by kind and measurement and, for a destination whose
verifier says more than a measurement (the Azure confidential GPU host),
carries `destination_detail`: the chip's product and id, the reported TCB,
the vTPM quote's PCR selection and digest, each GPU with who vouched for it,
and the verifier's own evaluations of the GPUs' reports (ADR 0021, amended).

**Confirm it landed.** The destination logs `crosscloud handshake answered` with
a `recipient_key_sha256` and a `recipient_key_suite`, then `crosscloud token
accepted` with the same `request_id` and `registered_keys`. The digest and the
suite must equal the report's `recipient_key_sha256` and `recipient_key_suite`:
they identify the one key the DEKs were sealed to, and under what.

**Audit it.** Anyone holding the audit public key can verify the log offline:

```bash
acpctl audit verify --audit /var/lib/acp/xcc-audit.db \
  --audit-pubkey sagvd-audit.pem --audit-kid sagvd-audit --json
```

It checks every hash link and signature and prints the tip. Keep the report's
`audit_tip`: a log whose tail was cut off still verifies, but not to that tip.
Re-releasing the same key under the same kid (a retry whose answer was lost) is
accepted once more; a different key under a kid the destination already holds
is refused.

## Confirming the restore

The destination restores on its own. Its account is on its API (same TLS and
token as the key release):

```bash
curl --cert client.crt --key client.key --cacert ca.crt -H "Authorization: Bearer $TOKEN" \
  https://destination.example.com:8443/v1/genome/restores
```

The source records the restore only from the destination's signed word:

```bash
sagvd crosscloud-confirm \
  -config /etc/acp/sagvd.json \
  -decision-id dec-2026-09-14-001 \
  -destination-endpoint https://destination.example.com:8443 \
  -bundle gen-1.genome -wait 2m
```

It reads the release from the verified audit log (never from flags), fetches the
destination's receipt, verifies the Evidence over it with the verifier for that
TEE family, and requires the measurement to be the one the key was released to
and the decision, request, token and key to be the recorded ones. With
`-bundle` it also requires the restored genome to be exactly the operator's —
bundle digest, payload digest and the digest of every restored file. With
`-require-gate EQUIVALENT` (or `EXACT`) it also requires the destination's gate
verdict on the restored model to be at least that. Only then does it append
`CROSS_CLOUD_RESTORE_COMPLETED`, recording the gate verdict with it. `-wait` keeps asking while the
restore is still running. The report carries the measurements:

```json
{
  "status": "ok",
  "key_id": "genome-…-g1-…",
  "tree_sha256": "…",
  "files": 3,
  "bytes": 3158206,
  "restore_seconds": 0.013,
  "key_to_restored_seconds": 0.014,
  "authorized_to_confirmed_seconds": 0.31,
  "matched_operator_bundle": true,
  "audit_chain_length": 4,
  "audit_tip": "…"
}
```

`key_to_restored_seconds` is measured on the destination's clock,
`authorized_to_confirmed_seconds` on the source's. A receipt that does not check
out is refused (`integrity`, or `authority` for a key that was not released under
that decision) and nothing is recorded.

## When a release is refused

| Report `error.category` | Audit events | Meaning | What to do |
|---|---|---|---|
| — (exit 1, no report) | none | Bad flags, `http://` to a remote host, or config/material failed to load | Fix the invocation or config; the message names the field |
| `operational` | handshake initiated | The handshake did not complete: destination unreachable, TLS refused (no client certificate, TLS below 1.3), bearer token rejected, or the destination refused the request — the message carries its answer (e.g. a TEE kind it does not run, an authority key it does not trust) | Check the listener, certificates, token, and the identities each side pinned |
| `integrity` | handshake initiated, release denied | Evidence did not verify for the presented key — wrong attestor key, wrong measurement, a replayed or substituted answer — or the destination presented no usable key | Treat an unexpected one as possible impersonation; re-check the pinned identities |
| `authority` | handshake initiated, attestation verified, release denied | The destination is genuine but the operator stop refuses it (the message names the list serial and reason), or its measurement is not on the allow-list | Intended: lift the stop with a newer list, or add the measurement to a new allow-list version, only if you mean to |
| `operational` | all three | The token did not reach the destination, or the destination refused it — the message carries its answer (no outstanding handshake: expired or used; decision mismatch; signature) | Run the command again: a new handshake mints a new key and the old one expires unused. If it repeats, read the destination's `crosscloud token rejected` log line |

## The operator stop

The people responsible for the deployment — not the release host, and not any
workload — decide whether keys may move at all (ADR 0010). On the operator's own
machine:

```bash
acpctl stop keygen -out operator.seed -pub operator.pem          # once; operator.pem goes to the release host
acpctl stop issue -key operator.seed -kid operator-1 -serial 1 -out stop.json          # nothing stopped
acpctl stop issue -key operator.seed -kid operator-1 -serial 2 -all \
  -reason "suspected compromise" -out stop.json                                         # stop every release
acpctl stop issue -key operator.seed -kid operator-1 -serial 3 \
  -revoke gcp-sev-snp:<measurement_hex> -reason "host decommissioned" -out stop.json    # revoke one destination
acpctl stop verify -in stop.json -pubkey operator.pem -kid operator-1                  # check before shipping
```

Copy the signed `stop.json` to `list_path` on the release host. Every
`crosscloud-restore` run reads it afresh:

- a stop, or a revoked destination, is refused with `authority /
  attestation_denied` and the list's serial and reason, and the refusal is in the
  audit log as `KEY_RELEASE_DENIED`;
- a list that is missing, edited, or signed by another key stops every release;
- a list older than the newest serial any recorded decision was made under is
  refused (`rollback refused`) — lifting a stop takes a newer list;
- the report names the list in force as `operator_stop_serial`.

Keep the operator seed off the release host: anyone holding it decides what the
fleet may do.

## Rotating what you trust

- **New destination measurement** (upgrade, new image): print its identity,
  write a new allow-list with a new `version`, set the same value as
  `policy_version`. Each `crosscloud-restore` run reads the files afresh. A
  `gcp-sev-snp-vtpm` destination's new boot is pinned the same way: add its
  identity's `vtpm.pcr_digest_hex` to the entry's `pcr_digests`
  (runbooks/real-tee-gcp-sev-snp-vtpm.md, D).
- **Revoking a destination:** remove its measurement from the allow-list (new
  version). No further key reaches it; keys it already holds stay where they are.
- **Authority key:** rotate the seed, run `sagvd identity`, re-pin
  `authority.pem` at every destination and restart `acp-bootstrap`; handshakes
  and tokens signed by the old key are then refused.
- **Bearer token:** replace the file at the destination (restart
  `acp-bootstrap`) and the value at the source together; it is defence in depth
  on top of the signatures.

## Security properties you can rely on

- Holding a token — with or without the measurement it names — reveals no DEK.
- A destination key opens exactly one token and dies after five minutes.
- The KEM suite is what the profiles of both sides accept, never less: a
  suite outside the source's list, or one swapped in transit, is refused
  before anything is verified or wrapped, and the record names the suite.
- A replayed handshake cannot replace an outstanding key; a forged token is
  rejected before it can use one up.
- Every release is preceded by the three audit events, in order, persisted to
  the signed log before the step they describe; every refusal after the
  handshake ends with `KEY_RELEASE_DENIED`.
- A restore is recorded only from Evidence of the TEE the key went to, over a
  receipt that names that release; the destination materialises nothing before
  every segment of the bundle has authenticated and every restored file matches
  the sealed snapshot.
- The operator's signed stop list is applied to every release; without a valid
  one, nothing is released, and an older list cannot be put back.

## Known limits

- The destination attests with real hardware only on SEV-SNP; other TEE families
  are refused on both sides until their producers and verifiers run end to end.
- Genome keys live in 0600 files on the release host; the source does not yet
  keep them sealed to its own TEE (KNOWN_ISSUES #11).

## Document history

| Date | Change |
|---|---|
| 2026-05-09 | Initial Phase 4 runbook |
| 2026-09-14 | Rewritten against the shipping binaries: X25519 KEM delivery (ADR 0009), `identity` subcommands, TLS 1.3 and fail-closed exposure; removed commands that do not exist |
| 2026-09-14 | Genome v3 sealing, `-key-file` releases, destination restore and `crosscloud-confirm` (ADR 0011) |
| 2026-10-21 | KEM suites and the cryptographic profile (ADR 0029): `crypto.profile`, the suite in the handshake, the token, the report, the log and the audit chain |

# Disaster Recovery runbook

| Last updated | 2026-09-14 |
|--------------|------------|
| Audience     | Platform operators, on-call SRE, security incident responders |
| Scope        | Single-tenant deployments; multi-tenant addenda flagged inline |
| Pair docs    | [Cross-cloud restore](../06_cross_cloud_restore.md) · [Triage table](../triage_table.md) · [Threat model](../../security/threat_model.md) |

This runbook is the single source of truth for what to do when
something has gone catastrophically wrong with a Vault Genome
deployment. Each scenario follows the same structure:

1. **Detection** — how the incident surfaces
2. **Immediate containment** — first 15 minutes
3. **Investigation** — what to confirm before recovery
4. **Recovery** — the restore-to-service procedure
5. **Post-mortem** — what to record before closing the incident

Every procedure is **operator-testable** in a staging environment.
Test it once a quarter. The first time you run it shouldn't be live.

## What this runbook assumes

- `sagvd` and `acp-compute` run with a JSON config passed as `-config PATH`
  and log JSON lines to stderr. No systemd unit or other service definition
  ships with this repository; the only packaged deployment is
  `deploy/compose/` (Docker Compose), where the equivalents of "stop" and
  "start" are `docker compose -f deploy/compose/docker-compose.yml stop sagvd`
  and `… start sagvd`.
- Both daemons read their key files, the worker registry, TLS files and the
  bearer token at startup only: a change takes effect at the next start.
- sagvd's job queue lives in memory; jobs queued or running when it stops
  are lost.
- Two audit logs, both under `keys.audit_signing`: the Return Path log
  (`audit.log_path`, every decision of the `sagvd` daemon before it takes
  effect, ADR 0014) and the cross-cloud log (`crosscloud.audit_log_path`,
  written by `sagvd crosscloud-restore`, `crosscloud-confirm` and `failover`).
- `sagvd`, `acp-compute` and `acp-bootstrap` attest with the hardware they
  run on — AMD SEV-SNP, Intel TDX or the Azure confidential GPU VM — or with
  the simulated TEE for development, which announces itself.

## Index

- [Scenario 1: Authority signing key compromised](#scenario-1-authority-signing-key-compromised)
- [Scenario 2: Session sealing key compromised](#scenario-2-session-sealing-key-compromised)
- [Scenario 3: TEE attestation root rotated by vendor](#scenario-3-tee-attestation-root-rotated-by-vendor)
- [Scenario 4: Vault Authority (sagvd) unreachable](#scenario-4-vault-authority-sagvd-unreachable)
- [Scenario 5: TEE hardware unavailable at a SEV-SNP destination](#scenario-5-tee-hardware-unavailable-at-a-sev-snp-destination)
- [Scenario 6: Audit log corruption or tampering detected](#scenario-6-audit-log-corruption-or-tampering-detected)
- [Scenario 7: Sealed genome bundle or key file deleted or corrupted](#scenario-7-sealed-genome-bundle-or-key-file-deleted-or-corrupted)
- [Scenario 8: Worker compromise (acp-compute identity mismatch)](#scenario-8-worker-compromise-acp-compute-identity-mismatch)
- [Scenario 9: Operator API credentials leaked](#scenario-9-operator-api-credentials-leaked)
- [Scenario 10: CI/CD pipeline compromise](#scenario-10-cicd-pipeline-compromise)

---

## Scenario 1: Authority signing key compromised

The authority signing key (`keys.authority_signing.seed_path`) is the
private half of the vault's identity. In this build it signs the cross-cloud
handshake requests and key-release tokens that every `acp-bootstrap`
destination verifies against its `source_authority` key. Anyone holding it can
sign handshakes and tokens that every destination pinning that key accepts.
(The sagvd daemon loads the key but its Return Path does not use it.)

### Detection

- A destination logs `crosscloud token accepted` (fields `token_id`,
  `request_id`, `decision_id`) for a `request_id` with no matching
  `KEY_RELEASE_AUTHORIZED` event in the source's audit log:
  `acpctl audit query --audit <audit log> --kind KEY_RELEASE_AUTHORIZED --json`
  prints the `request_id` of every release.
- An external party reports a signed artefact you don't recognise.
- Access to the seed file outside maintenance windows (host file-integrity
  or `auditd` alerts).

### Immediate containment (within 15 minutes)

1. **Cut off the destinations**: stop each `acp-bootstrap` listener, or block
   it at the network, until it pins a new key. The destinations are what
   accept forged handshakes and tokens; the operator stop list is enforced by
   sagvd, not by destinations, so it does not stop someone who holds the key.
2. **Stop sagvd's releases too**: sign a stop list with `-all`
   (`acpctl stop issue -key operator.seed -kid <kid> -serial <next> -all
   -reason "authority key compromise" -out stop.json`) and install it at
   `crosscloud.operator_stop.list_path`.
3. **Notify**: page the security incident response on-call;
   notify customers within 1 hour (BAA / SLA dependent).

### Investigation

- Copy the audit log (`crosscloud.audit_log_path`) off the host and list every
  release since the last known-good rotation:
  `acpctl audit query --audit <copy> --since <RFC 3339 time> --kind KEY_RELEASE_AUTHORIZED --json`.
- Compare that list with every destination's `crosscloud token accepted`
  lines; anything a destination accepted that the log does not hold was not
  released by this authority.
- Determine root cause: leaked seed file, supply-chain compromise of
  the binary, host-level compromise, or an operator credential leak that
  touched the seed.

### Recovery

1. **Generate a new authority signing seed** (32 bytes; sagvd reads exactly
   32 and does not check the file mode, so set it yourself):
   ```bash
   head -c 32 /dev/urandom > /etc/acp/secrets/sagvd/authority_signing_seed.NEW
   chmod 0600 /etc/acp/secrets/sagvd/authority_signing_seed.NEW
   ```
2. **Point the config at it and change the kid** (sagvd's JSON config):
   ```json
   "keys": {
     "authority_signing": {
       "kid": "sagvd-authority-2026-09-14",
       "seed_path": "/etc/acp/secrets/sagvd/authority_signing_seed.NEW"
     }
   }
   ```
3. **Print the new public key**: `sagvd identity -config <config>` →
   `authority_kid`, `authority_public_key_pem`.
4. **Re-pin every destination**: replace the file at
   `source_authority.public_key_path` and set `source_authority.kid`, then
   restart `acp-bootstrap`. Handshakes and tokens signed by the old key are
   refused from then on (06, "Rotating what you trust").
5. **Restart sagvd**. At startup it logs `sagvd authority signing identity`
   with the new `kid` and `pubkey_hex`.
6. **Lift the stop** with a stop list of a higher serial when you are ready
   to release again.

### Post-mortem

- Record the incident in your incident tracker.
- Update `docs/security/threat_model.md` if the threat scenario
  surfaced was not already documented.
- Schedule the next rotation (default annual; tighten to quarterly after a
  real compromise). Keys carry no expiry in the config, so the calendar is
  the only reminder.

---

## Scenario 2: Session sealing key compromised

The session sealing key (`keys.session_sealing`: `kid`, `material_path`) is
the AES-256 key shared by sagvd and every `acp-compute`. sagvd seals every
component of a gate job under it into the JobRequest's `SealedMaterialRef`s —
the genome's description, its LoRA adapter, the fixtures' prompts; the worker
opens them with the same kid. A compromise means anyone who captured
JobRequest bytes from the Return Path can decrypt the adapters that were
shipped.

### Detection

- Sealing key file modified or read outside maintenance windows
  (`auditd` or file-integrity alerts on the key directory).
- The key material found anywhere it should not be.

### Immediate containment

1. Stop sagvd and every acp-compute.
2. Notify security on-call.
3. **DO NOT delete the file yet** — forensic team needs the bytes.

### Investigation

- List the jobs that ran under the key: sagvd logs `sagvd dispatching job`
  (`job_id`, `manifest_id`, `session_id`) for every job. Job records
  themselves live only in memory.
- Determine whether Return Path traffic could have been captured: off
  loopback it is mutual TLS 1.3, so a capture also implies a TLS key or host
  compromise — treat that as the primary incident (Scenario 8).

### Recovery

1. Generate a new 32-byte key:
   ```bash
   head -c 32 /dev/urandom > /etc/acp/secrets/shared/sealing.key.NEW
   chmod 0600 /etc/acp/secrets/shared/sealing.key.NEW
   ```
2. Point `keys.session_sealing.material_path` at it and change
   `keys.session_sealing.kid` — in sagvd **and** in every acp-compute. The
   kid and the bytes must match on both sides: the worker opens each
   component with the kid carried on the wire.
3. Start sagvd and the workers. sagvd logs `sagvd session sealing identity`
   with the new kid.
4. **Every adapter shipped under the old key is suspect** — surface to
   customers per BAA; the genomes themselves stay sealed under their own
   keys in `genome.bundle_dir`, which this key never opened.

---

## Scenario 3: TEE attestation root rotated by vendor

Cloud TEE vendors rotate their attestation root certificates
periodically. The only hardware verifier the shipped binaries run is AMD
SEV-SNP, in sagvd's cross-cloud verifier registry: each `gcp-sev-snp` entry
pins the AMD ASK + ARK chain in `amd_cert_chain_path`, fetches each chip's
VCEK from AMD KDS (or the mirror in `amd_kds_url`) and keeps fetched VCEKs in
`vcek_cache_dir`. Verifiers for other families are refused by the registry.

### Detection

- `sagvd crosscloud-restore` refuses every SEV-SNP destination with
  `integrity`, the message naming `gcp-sev: AMD chain:` or
  `gcp-sev: fetch VCEK:`, and the audit log records `KEY_RELEASE_DENIED`.
- AMD announces a change via security advisory.

### Immediate containment

- Continue releasing with stale roots: NO. The verifier fails closed, so
  nothing is released while the pinned chain is out of date — keep it that
  way until the new chain is checked.

### Recovery

1. Fetch AMD's current chain for the product from KDS (for Milan:
   `https://kdsintf.amd.com/vcek/v1/Milan/cert_chain`) and check it through a
   second channel.
2. Replace the file at `amd_cert_chain_path` in `verifiers.json`.
3. Remove the cached VCEKs in `vcek_cache_dir` so they are fetched again and
   checked against the new chain (a cached certificate is re-checked against
   the pinned chain on every use; one that no longer chains will keep failing).
4. Run `sagvd crosscloud-restore` again. It reads `verifiers.json` afresh on
   every run; there is no daemon to restart.
5. If a destination still fails, escalate to the vendor. After an AMD TCB
   advisory, raise `min_reported_tcb` so reports from older firmware are
   refused.

### Post-mortem

- Record the rotation date; calendar the next expected one
- Update [`docs/security/threat_model.md`](../../security/threat_model.md)
  cross-platform residual #3 if the rotation surfaced a new gap

---

## Scenario 4: Vault Authority (sagvd) unreachable

### Detection

- Workers log `return-path cycle failed` repeatedly, with a growing
  `backoff_ms`.
- The health listener (`health.listen_address`, default `127.0.0.1:9091`)
  does not answer `/healthz`, or answers 503 `unhealthy` (only during
  shutdown).
- Prometheus `up{job="sagvd"} == 0`, if you scrape `/metrics` under the job
  name `deploy/grafana` assumes.

### Triage

```
Does /healthz answer on the health listener?
├── No  → Is the process alive?
│         ├── Yes → hung: capture goroutine stacks (below), restart
│         └── No  → read stderr: the last line is "sagvd: terminated with error"
│                   and its "err" names the cause (config field, key file,
│                   "listen" error: port in use or not permitted)
└── Yes → Does /readyz answer "ready"?
          ├── No  → the Return Path listener is not bound yet (or is shutting down)
          └── Yes → sagvd is up; the problem is between worker and sagvd:
                    network path, mTLS material, TEE pins
                    ("sagvd TLS handshake failed", "sagvd return-path handshake failed")
```

### Recovery

1. **If the process is alive but unresponsive**: sagvd installs no
   stack-dump handler, but the Go runtime's default SIGQUIT handling
   (`kill -QUIT <pid>`) prints every goroutine's stack to stderr and exits.
   Keep that output, then restart.
2. **If startup fails**: fix what the `err` field names — a config validation
   list (`sagvd: config validation: …`), a key file of the wrong length
   (`… must be exactly 32 bytes (got N)`), or a bind error
   (`sagvd: listen …`, `sagvd: HTTP API listen …`, `sagvd: health server: …`).
3. **After a restart**: jobs that were queued or running are gone (the queue
   is in memory) — resubmit them. Workers reconnect by themselves.

---

## Scenario 5: TEE hardware unavailable at a SEV-SNP destination

Every daemon that runs with a hardware provider needs that hardware at
start; this scenario is written for an `acp-bootstrap` destination running
with `tee.provider: "gcp-sev-snp"` and applies the same way to `sagvd` and
`acp-compute` on `gcp-sev-snp`, `gcp-tdx` (configfs-tsm as well) or
`azure-cgpu` (the vTPM, tpm2-tools and the GPU). `gcp-sev-snp` requests
attestation reports through the kernel's configfs-tsm (`tee.tsm_report_dir`, default
`/sys/kernel/config/tsm/report`; Linux 6.7 or later).

### Detection

- `acp-bootstrap` (or `acp-bootstrap identity`) exits at startup with
  `gcp-sev: no configfs-tsm report directory at … (this binary must run inside
  a Confidential VM on Linux 6.7 or later)` or `gcp-sev: initial report: …`.
- `crosscloud-restore` to that destination fails with `operational`
  (unreachable).
- The cloud console reports the Confidential VM unhealthy.

### Investigation

| Check | If it fails |
|-------|-------------|
| `ls /sys/kernel/config/tsm/report` on the guest | Not a SEV-SNP guest, a kernel older than 6.7, or configfs not mounted |
| `dmesg \| grep -i sev` shows SEV-SNP active | The VM was not launched as a SEV-SNP Confidential VM |
| `acp-bootstrap identity -config …` prints the expected `measurement_hex` | Image or firmware changed (below) |

### Recovery

1. **If the hardware is healthy but the guest is not** (wrong kernel, no
   configfs-tsm), rebuild the guest from the known-good image
   ([real-tee-sev-snp.md](real-tee-sev-snp.md) §A, §D).
2. **If the host is unhealthy**, move to another SEV-SNP VM. Its launch
   measurement can differ — the guest firmware differs between zones
   (`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/README.md`) — so run
   `acp-bootstrap identity`, put the new measurement in `verifiers.json` and
   in an allow-list with a new `version` (and set `crosscloud.policy_version`
   to the same value), replicate the sealed bundles into its
   `genome.bundle_dir`, and release the keys again with `crosscloud-restore`
   (06).
3. **If no other SEV-SNP host is available**: declare unavailability;
   communicate per SLA.

---

## Scenario 6: Audit log corruption or tampering detected

The audit log (`crosscloud.audit_log_path`, a bbolt file written through
`internal/audit/store`) is a hash chain signed under `keys.audit_signing`.
Any break in the chain is detected whenever it is verified.

### Detection

- `sagvd crosscloud-restore` or `crosscloud-confirm` stops with
  `the stored audit log does not verify; refusing to extend it` — the log is
  verified end to end every time it is opened.
- `acpctl audit verify` prints `audit chain BROKEN: …` naming
  `event #N: prev_hash does not link to event #N-1` (or `event #N: …` for a
  bad signature) and exits 4.
- Its event count or tip no longer matches the latest kept report (a cut-off
  tail still verifies; only this comparison shows it — 04 §2.2).
- bbolt file size changes in unexplained ways; `auditd` reports
  unexpected file modification.

### Immediate containment

1. **Run no releases.** sagvd will not append to a log that does not verify,
   so they fail anyway.
2. Copy the file off the host before anything else touches it
   (`scp <audit log> forensics-host:/...`). Run acpctl on the copy: it opens
   the file read-write.
3. There is no repair command, by design — keep the corruption visible for
   investigation.

### Investigation

- `acpctl audit verify` on the copy names the first broken event (N).
- `acpctl audit query --audit <copy> --limit 0 --json` lists every event
  (it checks no hashes or signatures, so it works on a broken chain);
  correlate the events around N with the system journal and the kept reports.
- Determine: did the corruption come from outside (host compromise)
  or from within (a bug)?

### Recovery

- **If corruption came from outside**: this is a host compromise.
  Treat as Scenario 1 + 2 simultaneously; rotate every key, including
  `keys.audit_signing`.
- **If it is a bug**: file an incident ticket. The corrupted file is the
  artefact you keep — you don't "repair" it. Keep it read-only for forensic
  and regulatory reference and point `crosscloud.audit_log_path` at a new
  file, which starts a new chain.
- **A new log resets the stop-list rollback check**, which reads the log's
  history: sign and install a stop list whose serial is above every serial you
  have used before releasing again.

---

## Scenario 7: Sealed genome bundle or key file deleted or corrupted

A sealed genome is a v3 bundle (`*.genome`) plus a separate 0600 key file.
`acpctl genome seal` writes the key only to `--key-out`; nothing else keeps
it. Bundles are opaque without their keys and can be replicated anywhere;
key files cannot be recreated.

### Detection

- `acpctl genome verify --bundle X.genome --key-file X.key` fails
  (`acpctl genome inspect --bundle X.genome` reads the header without the
  key).
- The file is missing or its size is unexpected.
- A destination never restores the bundle, or `crosscloud-confirm -bundle`
  reports that the restored genome does not match the operator's bundle.

### Recovery

1. **First**: do not panic. A bundle can be restored from any replica — it
   is useless without its key.
2. **Restore the bundle** from a replica or backup, and the key file from its
   separate, access-controlled backup.
3. **Validate**: `acpctl genome verify --bundle X.genome --key-file X.key`
   (add `--restored DIR` to check a restored tree against the seal).
4. **If the key file is lost**, the bundle cannot be opened. The only path is
   to seal the source again (`acpctl genome seal`), which produces a new key
   and key ID.

### Prevention

- Back up key files separately from bundles, to an off-host location with
  its own access control.
- Replicate bundles freely; they are sealed.

`acpctl recover` is a different tool: it unseals a `VG-VAULT-01` envelope
with the TEE backend the envelope names, and no shipped binary writes that
format yet. Its `--dry-run` only decodes the envelope and probes whether that
backend is available on the host (it reports `sealed_bytes` and
`capability_available`); `--vault` is always required.

---

## Scenario 8: Worker compromise (acp-compute identity mismatch)

sagvd pins exactly one worker TEE identity — `tee.peer.public_key_path` and
`tee.peer.measurement_path` (for the simulated TEE, the SHA-256 of the
worker's `tee.workload_descriptor`) — and accepts CandidateOutputFrame
signatures only from the kids in `workers.registry_path`.

### Detection

- `vg_tee_attestation_total{provider="simulated",result="error",role="verify"}`
  and `sagvd_handshake_failures_total{phase="handshake"}` rise; sagvd logs
  `sagvd return-path handshake failed`.
- sagvd logs `sagvd worker signature verification failed` with a
  `worker_kid` — a candidate signed by a key or kid it does not accept.
- `sagvd job completed` lines show a `worker_signing_kid` you did not expect.

### Immediate containment

1. **Stop accepting the worker**: remove its entry from
   `workers.registry_path` and restart sagvd. The registry schema is
   `{"workers": [{"kid", "signing_pubkey_hex", "note"}]}` and unknown fields
   are rejected, so there is no deny-list field — deletion is the mechanism.
   A registry with no entries stops sagvd from starting.
2. If the worker's TEE seed is suspect, also stop sagvd from accepting that
   TEE identity: until a rebuilt worker exists, keep sagvd stopped or its
   Return Path unreachable.
3. Notify security incident on-call.

### Investigation

- Rebuild the worker host from a known-good image and compare its config
  (`tee.workload_descriptor`, key files) with what sagvd pins.
- Audit the worker host for unauthorised changes (file integrity
  monitoring, intrusion detection).

### Recovery

1. Give the rebuilt worker a new TEE seed and a new worker signing seed
   (`tee.seed_path`, `keys.worker_signing`; `deploy/compose/keygen` shows how
   the pinned files are produced).
2. Put its TEE public key and measurement at sagvd's `tee.peer.public_key_path`
   and `tee.peer.measurement_path`, and its new kid and public key (from the
   worker's `worker signing identity` startup log line) in
   `workers.registry_path`.
3. Restart sagvd; confirm `sagvd accepted worker signing identity` names the
   new kid and `sagvd session opened` follows.

---

## Scenario 9: Operator API credentials leaked

`POST /v1/jobs` and `GET /v1/jobs/{id}` are served over plain HTTP — the
`http_api` section has no TLS settings. A bearer token (`http_api.bearer_token`
or `bearer_token_file`, at least 32 characters) is mandatory when
`http_api.listen_address` is not loopback, optional on loopback. Anyone on the
network path can read the token, so keep the API on loopback or behind your
own TLS terminator.

### Detection

- `sagvd_jobs_submitted_total` or
  `sagvd_http_requests_total{route="/v1/jobs",status="202"}` jumps without a
  matching workload.
- `auditd` alert on the token file.
- Public dump (Pastebin / GitHub gist) discovery.

### Immediate containment

1. **Collect the job history first**: it lives in sagvd's memory and a
   restart clears it. There is no job-listing endpoint (`GET /v1/jobs`
   answers 405); read the `job_id` values from the `sagvd dispatching job`
   log lines and fetch each with `GET /v1/jobs/{id}`.
2. Write a new token to `bearer_token_file` and restart sagvd — the token
   is read only at startup. The old token stops working at that restart.
3. Lock down the old credentials file mode (`chmod 0000`) until rotation
   completes — prevents accidental further use.

### Recovery

1. Issue the new token to the legitimate operator out-of-band.
2. Review the jobs submitted during the credential's lifetime against
   the operator's expected workload. sagvd does not log REST API client
   addresses; use your proxy or network logs for that. Any unexpected submission is a
   data-exposure incident — escalate per BAA notification clause.

---

## Scenario 10: CI/CD pipeline compromise

### Detection

- Releases appear without corresponding signed tags
- `cosign verify-blob` against released binaries fails
- SLSA provenance attestation references a workflow run that doesn't
  exist in the GitHub Actions log

### Immediate containment

1. **Pause releases**: disable the `release.yml` workflow at the
   GitHub Actions admin level.
2. **Notify customers**: if customers have already pulled an
   unverifiable binary, advise them to roll back to the most recent
   verifiable version.

### Investigation

- Reconstruct the release log from sigstore Rekor — every legitimate
  release entry has a transparency log entry whose `subject` matches
  a published binary. Anything in Rekor for a workflow run that's
  not in our GHA history is a forgery — escalate to GHA support.
- Determine if the compromise is read-only (attacker observed our
  pipeline) or active (attacker pushed a malicious workflow).

### Recovery

1. Rotate every secret the workflows can read (repository and
   organisation Actions secrets, deploy keys).
2. cosign keyless means there is no long-lived signing key to rotate;
   the rotation here is confined to the tokens and secrets the workflows
   use.
3. Replay the most recent legitimate release through a fresh
   workflow run; bump the patch version (`vX.Y.Z+1`) to make
   downstream cache invalidation clean.
4. Notify the SLSA / sigstore community of any abuse if the
   compromise touched their infrastructure.

---

## Quarterly DR exercise

Once a quarter, run the following in staging:

| Scenario | Procedure | Pass criterion |
|----------|-----------|-----------------|
| 1 (auth-signing rotation) | Generate a new seed, update the config, run `sagvd identity`, re-pin a destination, restart both | Startup log shows the new kid; a `crosscloud-restore` to the re-pinned destination succeeds |
| 7 (sealed genome restore) | Delete a bundle copy, restore it from its replica, run `acpctl genome verify --bundle … --key-file …` | Exit 0 |
| 4 (sagvd unreachable) | Stop the daemon, observe the workers' `return-path cycle failed` lines and any alerts, restart | `/readyz` answers `ready` and `sagvd session opened` appears within 60 s of restart |

Record the results with your incident records. The first failed exercise
produces an incident ticket; the runbook is updated and the exercise re-run
within 30 days.

---

_Document history: 2026-09-14 — checked line by line against the code; commands and names the binaries do not have were removed._

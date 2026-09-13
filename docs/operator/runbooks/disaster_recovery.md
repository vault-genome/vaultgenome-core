# Disaster Recovery runbook

| Last updated | 2026-05-06 |
|--------------|------------|
| Audience     | Platform operators, on-call SRE, security incident responders |
| Scope        | Phase 1 single-tenant deployments; multi-tenant addenda flagged inline |
| Pair docs    | [`acpctl recover` reference](../acpctl-recover.md) · [Threat model](../../security/threat_model.md) |

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

## Index

- [Scenario 1: Authority signing key compromised](#scenario-1-authority-signing-key-compromised)
- [Scenario 2: Session sealing key compromised](#scenario-2-session-sealing-key-compromised)
- [Scenario 3: TEE attestation root rotated by vendor](#scenario-3-tee-attestation-root-rotated-by-vendor)
- [Scenario 4: Vault Authority (sagvd) unreachable](#scenario-4-vault-authority-sagvd-unreachable)
- [Scenario 5: TEE hardware unavailable / enclave fails to start](#scenario-5-tee-hardware-unavailable--enclave-fails-to-start)
- [Scenario 6: Audit log corruption or tampering detected](#scenario-6-audit-log-corruption-or-tampering-detected)
- [Scenario 7: Sealed material file deleted or corrupted](#scenario-7-sealed-material-file-deleted-or-corrupted)
- [Scenario 8: Worker compromise (acp-compute MRENCLAVE mismatch)](#scenario-8-worker-compromise-acp-compute-mrenclave-mismatch)
- [Scenario 9: Operator API credentials leaked](#scenario-9-operator-api-credentials-leaked)
- [Scenario 10: CI/CD pipeline compromise](#scenario-10-cicd-pipeline-compromise)

---

## Scenario 1: Authority signing key compromised

The authority signing key (`keys.authority_signing.seed_path`) is the
private half of the vault's identity. A compromise means an attacker
can mint authority artefacts (release decisions, validation verdicts)
that downstream consumers will accept.

### Detection

- Unexpected release decisions in audit log (`internal/audit/store/`)
- An external party reports they observed a signed artefact you don't
  recognise
- govulncheck flags the artefact with the kid you've rotated away from

### Immediate containment (within 15 minutes)

1. **Stop sagvd**: `systemctl stop vault-genome-sagvd` on every node.
2. **Add the compromised kid to the worker registry's deny-list**: edit
   `workers.registry_path` and set `denied_authority_kids: ["<kid>"]`
   on the workers' side (so any in-flight or queued artefact signed
   under the compromised key is rejected by the receive validator).
3. **Notify**: page the security incident response on-call;
   notify customers within 1 hour (BAA / SLA dependent).

### Investigation

- Recover the audit log (`/var/lib/vault-genome/audit.bbolt`) and
  inventory every artefact signed by the compromised kid since the
  last known-good rotation.
- Confirm via `acpctl status --since <last-rotation-iso>` (Phase 2 CLI)
  which sessions are in scope.
- Determine root cause: leaked key file, supply-chain compromise of
  the binary, host-level compromise (SGX side-channel? Nitro
  hypervisor? Operator credential leak that touched the seed?).

### Recovery

1. **Generate a new authority signing keypair**:
   ```bash
   head -c 32 /dev/urandom > /etc/vault-genome/auth-signing.seed.NEW
   chmod 0400 /etc/vault-genome/auth-signing.seed.NEW
   chown vault-genome:vault-genome /etc/vault-genome/auth-signing.seed.NEW
   ```
2. **Rotate the kid in `sagvd.yaml`**:
   ```yaml
   keys:
     authority_signing:
       key_id: "auth-signing-2026-05-06"   # bump
       seed_path: /etc/vault-genome/auth-signing.seed.NEW
   ```
3. **Restart sagvd**: `systemctl start vault-genome-sagvd`. The new
   kid + pubkey are emitted at startup; cross-check via
   `journalctl -u vault-genome-sagvd | grep "authority signing identity"`.
4. **Distribute the new pubkey** to every worker out-of-band (e.g.,
   signed PR to the worker registry repo). Workers need the pubkey
   for `recvvalidator` to accept future artefacts.
5. **Republish CRL / deny-list entry** for the compromised kid via
   the workers' configuration channel.

### Post-mortem

- Record incident in `business/incidents/INC-YYYY-MM-DD.md` (private repo)
- Update `docs/security/threat_model.md` if the threat scenario
  surfaced was not already documented
- Calendar review: confirm the new kid expires before the next
  scheduled rotation date (default annual; tighten to quarterly after
  a real compromise)

---

## Scenario 2: Session sealing key compromised

The session sealing key is the symmetric AES-256 material used to
seal `SealedMaterialRef` payloads. A compromise means an attacker
who has captured sealed bytes can decrypt them.

### Detection

- Sealing key file modified outside maintenance windows
- Unauthorised access to the keystore directory (`auditd` alert on
  `/etc/vault-genome/`)
- Rapid burst of `Unseal` failures suggesting an attacker is trying
  variants

### Immediate containment

1. Stop sagvd; mark the kid as deprecated in `sagvd.yaml`.
2. Notify security on-call.
3. **DO NOT delete the file yet** — forensic team needs the bytes.

### Investigation

- Inventory sessions issued under the compromised kid via the audit log.
- For each session, determine whether the candidate output was already
  released to the worker — if so, the plaintext is already on the
  worker's host (compromised TEE measurement?) and the sealing
  compromise is downstream of the TEE compromise; treat the TEE side
  as the primary incident (Scenario 5 / 8).

### Recovery

1. Generate a new 32-byte AES-256 key:
   ```bash
   head -c 32 /dev/urandom > /etc/vault-genome/session-sealing.key.NEW
   chmod 0400 ... && chown vault-genome:vault-genome ...
   ```
2. Rotate the kid; restart sagvd.
3. **All sealed material under the old kid is now suspect** — surface
   to customers per BAA. Workers' previously-received `SealedMaterialRef`s
   must be discarded; a fresh issuance cycle begins under the new kid.
4. If `acpctl recover` was used to back up sealed material, that
   archive is also suspect — destroy it and re-emit from the source
   genome.

---

## Scenario 3: TEE attestation root rotated by vendor

Cloud TEE vendors rotate their attestation root certificates
periodically. AWS Nitro PCA root rotation is rare (announced 90 days
in advance); Intel SGX Root rotations follow Intel TCB Recovery Events
(unscheduled, irregular).

### Detection

- All Verify calls fail with `aws-nitro: cert chain: ...` or
  `intel-sgx: dcap verify: ...`
- Vendor announces TCB Recovery via security advisory
- `vg_tee_attestation_total{result="error"}` counter spikes

### Immediate containment

- Continue running with stale attestation: NO. The attestation
  becomes a no-op security control. Stop sagvd until the new root is
  trusted.

### Recovery

1. Fetch the new published root from the vendor's documented URL:
   - AWS: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
   - Intel: https://api.trustedservices.intel.com/sgx/certification/v4/rootcacrl
   - AMD: https://developer.amd.com/sev/ (ARK / ASK)
   - Azure: MAA endpoint's `/certs` JWKS auto-rotates; no manual step
2. For pinned-root deployments, update the `PinnedRoots` field in
   `tee.AzureSGXVerifierConfig` / `tee.AWSNitroVerifierConfig` /
   etc. via the daemon's config file.
3. For PCCS-backed Intel SGX deployments, refresh the local PCCS:
   ```bash
   sudo systemctl restart pccs   # forces Intel collateral re-fetch
   ```
4. Restart sagvd; observe `vg_tee_capability_total{available="true"}`
   recover.
5. **Rerun `acpctl recover --dry-run`** on every sealed vault to
   confirm policy still passes under the new root. If recovery fails
   under the new root for a vault that succeeded under the old one,
   the vendor's rotation policy MAY have invalidated the sealing
   binding — vendor support escalation; in the worst case treat as
   Scenario 7 (sealed material loss).

### Post-mortem

- Record the rotation date; calendar the next expected one
- Update [`docs/security/threat_model.md`](../../security/threat_model.md)
  cross-platform residual #3 if the rotation surfaced a new gap

---

## Scenario 4: Vault Authority (sagvd) unreachable

### Detection

- Workers' `acp-compute` log: `dial sagvd: timeout`
- HTTP API `/healthz` returning 503 or no response
- Prometheus `up{job="sagvd"} == 0`

### Triage decision tree

```
                Is /healthz down on the host?
                        │
              ┌─────────┴─────────┐
              │                   │
            Yes                  No
              │                   │
   Is the process alive?  Is the listener bound?
              │                   │
        ┌─────┴──────┐    ┌───────┴────────┐
        │            │    │                │
       Yes          No   Yes              No
        │            │    │                │
  Crash? OOM?  Boot loop? Network ACL?  Listener bind error?
        │            │                     │
   journalctl    LoadMaterials       Port already in use?
   `/var/log/`     failed?           SELinux denial?
```

### Recovery

1. **If process alive but unresponsive**: capture goroutine dump via
   `pkill -SIGUSR1 sagvd` (Phase 2 — currently no SIGUSR1 handler;
   fallback: `kill -SIGABRT` to crash with stack trace). Restart.
2. **If LoadMaterials fails**: usually a config error or a missing
   keystore file. Check `journalctl -u vault-genome-sagvd | tail`
   for the specific Structural error.
3. **If hardware unavailable** (TEE backend reports `Capability` =
   false): see Scenario 5.
4. **If multi-region failover available**: route operator API traffic
   to the standby region; standby's sagvd has a fresh job queue but
   shares the audit log via cloud storage replication.

### Time-to-recover SLO

- Phase 1 single-region: **30 minutes** typical; 2 hours worst case
  if hardware re-provisioning needed
- Phase 2 multi-region: **5 minutes** to traffic-shift; 30 minutes
  to restore the failed region

---

## Scenario 5: TEE hardware unavailable / enclave fails to start

### Detection

- `vg_tee_capability_total{available="false",provider="<x>"}` ≥ 1 at startup
- `journalctl -u vault-genome-sagvd | grep "TEE backend"` shows the
  Capability error
- AWS console / Azure portal / GCP console reports the parent
  instance unhealthy

### Investigation

| Provider | First check | If first check passes |
|----------|-------------|------------------------|
| `aws-nitro` | `nitro-cli describe-enclaves` shows the enclave running | check `/dev/nsm` exists in enclave |
| `azure-sgx` | `lsmod \| grep sgx` shows the driver | check `/dev/sgx_enclave` permissions |
| `gcp-sev-snp` | `cat /proc/cpuinfo \| grep sev_snp` | check `/dev/sev-guest` exists |
| `intel-sgx-dcap` | BIOS shows SGX enabled, `lsmod \| grep sgx` | check PCCS reachable |

### Recovery

1. **If the underlying hardware is healthy but the binary is not in
   the enclave** (e.g., parent EC2 booted but enclave didn't), restart
   the enclave: `nitro-cli run-enclave --image vault-genome.eif ...`.
2. **If the hardware is unhealthy** (failed CPU, motherboard, …),
   migrate to a redundant node. acpctl recover restores the sealed
   material on the new node provided the new enclave's PCR0 /
   MRENCLAVE / launch-MEASUREMENT matches the envelope's pinned
   identity.
3. **If no redundant node available**: declare unavailability;
   communicate per SLA.

---

## Scenario 6: Audit log corruption or tampering detected

The audit log (`internal/audit/store/`, bbolt-backed) maintains a
hash chain. Any break in the chain is detected on `Verify` and
raises an Integrity event.

### Detection

- `internal/audit/chain` Verify call logs `chain inconsistency at
  height N`
- bbolt file size grows in unexplained ways
- `auditd` reports unexpected file modification

### Immediate containment

1. **Stop sagvd** to prevent further writes that would extend a
   compromised chain.
2. Snapshot the bbolt file off-host (`scp /var/lib/vault-genome/audit.bbolt
   forensics-host:/...`).
3. **Do not run `acpctl audit verify --repair`** — repair is not
   what you want; you want to keep the corruption visible for
   investigation.

### Investigation

- Use `acpctl audit verify` (Phase 2) to find the height at which the
  chain broke.
- Cross-reference timestamps with system journal (`journalctl
  --since="<break-time minus 10 min>"`).
- Determine: did the corruption come from outside (host compromise)
  or from within (sagvd bug)?

### Recovery

- **If corruption came from outside**: this is a host compromise.
  Treat as Scenario 1 + 2 simultaneously; rotate every key.
- **If corruption is a sagvd bug**: file an INC ticket; the audit
  log persistence IS the source of truth. The corruption itself is
  the artefact you're keeping; you don't "repair" it. Future
  artefacts go to a fresh chain (`audit.bbolt.NEW`); the old chain
  stays read-only for forensic and regulatory reference.

---

## Scenario 7: Sealed material file deleted or corrupted

### Detection

- `acpctl recover --vault X --dry-run` returns "vault decode: ..."
- File size is zero / unexpected
- Backup ingestion fails

### Recovery

1. **First**: do not panic. Sealed material is by design recoverable
   if the original genome (or its source-of-truth backup) still
   exists.
2. **Restore from backup**: `aws s3 cp s3://vault-bucket/...` /
   `gsutil cp gs://...`. Backups are 7-year-retained per VG-016.
3. **Validate**: `acpctl recover --vault X --dry-run --json` to
   confirm the restored envelope decodes and capability is available.
4. **If no backup exists** (operator misconfiguration), the only path
   is to re-issue from the source genome, which means a full
   re-deployment cycle. Cost varies; expect 2–4 hours.

### Prevention

- Cloud Storage versioning (Terraform module enables it by default)
- Snapshot the sealed-material directory daily via
  `restic` / `borgbackup` to an off-host, off-cloud location

---

## Scenario 8: Worker compromise (acp-compute MRENCLAVE mismatch)

### Detection

- `vg_tee_attestation_total{provider="<x>",result="error",role="verify"}`
  spikes
- sagvd's audit log shows handshake-failure events with
  `phase=tee_verify` for one or more workers
- Worker sends a candidate output signed by an unknown kid

### Immediate containment

1. **Refuse to issue further sessions to the worker**: deny-list the
   worker's kid in the workers registry on sagvd.
2. **Lock the bbolt audit log** (it stays append-only by construction;
   nothing extra to do).
3. Notify security incident on-call.

### Investigation

- Pull the offending worker's enclave image and rebuild — does the
  expected MRENCLAVE match what was attested? If yes, attacker
  forged an attestation (very high-skill); if no, the worker was
  rebuilt under unauthorised changes.
- Audit the worker host for unauthorised changes (file integrity
  monitoring, intrusion detection).

### Recovery

- Rebuild the worker's enclave from a known-good source
- Add the rebuilt MRENCLAVE to the verifier's `AcceptableMRENCLAVES`
  set in `sagvd.yaml`
- Remove the deny-listed kid from the registry; restart sagvd

---

## Scenario 9: Operator API credentials leaked

(POST `/v1/jobs` requires bearer token + mTLS client cert.)

### Detection

- Unusual `/v1/jobs` POST volume from operator IPs not on the allowlist
- `auditd` alert on the credentials file
- Public dump (Pastebin / GitHub gist) discovery

### Immediate containment

1. Revoke the leaked credential at the ingress gateway (rate-limit to
   zero, return 403). The operator's mTLS client cert can be revoked
   via CRL / OCSP on the path between the operator and sagvd's HTTP
   API.
2. Lock down the credentials file mode (`chmod 0000`) until rotation
   completes — prevents accidental further use.

### Recovery

1. Issue a fresh credential to the legitimate operator out-of-band
2. Update the workers registry / ingress gateway CRL with the
   revoked cert's serial number
3. Audit `/v1/jobs` POST history for the revoked credential's lifetime
   to determine which jobs were submitted under it; cross-check with
   the operator's expected workload. Any unexpected submission is a
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

1. Rotate every secret in GitHub Actions: pull-request token, deploy
   keys, AWS / GCP / Azure deployment credentials.
2. Force-rotate every signing-key reference; cosign keyless means
   there is no long-lived signing key, so the rotation here is
   confined to the pull/push tokens used by the workflow itself.
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
| 1 (auth-signing rotation) | Generate new key, update config, restart, confirm new kid in startup log | New kid visible; old kid in deny list |
| 7 (sealed material restore) | Wipe a sealed vault, restore from backup, run `acpctl recover --dry-run --json` | OK status, plaintext_bytes > 0 |
| 4 (sagvd unreachable) | Stop the daemon, observe Prometheus alerts firing, restart, confirm recovery | `up{job="sagvd"} == 1` within 60 s of restart |

Record the results in `business/dr-exercises/QQ-YYYY.md` (private
repo). The first failed exercise produces an INC ticket; the
runbook is updated and the exercise re-run within 30 days.

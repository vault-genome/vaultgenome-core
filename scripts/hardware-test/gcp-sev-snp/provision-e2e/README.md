# provision-e2e — a deployment stood up by one command on SEV-SNP

The returnpath-e2e guest with its hand-made provisioning replaced by
`acpctl provision` (P1-4): on a fresh n2d SEV-SNP Confidential VM the
command runs the release's `acp-keygen`, writes both daemons'
configurations for the family configfs-tsm says (`--provider auto`),
fetches the Milan chain from AMD KDS and verifies it against the pinned
roots, reads each daemon's identity from the chip and pins it on the
other side, keeps the operator's token and the audit public key under
`operator/`, and seals every key file to the chip's derived key. Then the
real `vg_genome` worker fine-tunes a genome, `acpctl` seals it into the
genome directory provision made, both daemons start on what it wrote, a
gate job goes over the Return Path and comes back EXACT, and the audit
log verifies under the key provision kept.

```bash
scripts/hardware-test/gcp-sev-snp/provision-e2e/run.sh <project> [zone]   # ~15 min, one n2d-standard-4
```

The results (`evidence/<stamp>/`): `provision.out` (what the command
printed — never a secret), `provision.json`, the two identities, the two
configurations (paths, no secret), `sealed-files.txt` (every key file's
sealer and size), `steps.txt`, `timeline.txt`, `job.json`, the daemons'
logs and metrics, `audit-verify.json`, `audit-events.jsonl`,
`audit-public-key.pem`, `sha256sums.txt`.

Run on record: `evidence/20261016T222951Z/` (claim C37) — an
n2d-standard-4, Milan: `acpctl provision` in 10.6 s (the chain from KDS,
both identities `7dc7c12e…5acc` from the chip, eight key files sealed to
the chip's derived key), the handshake 232 ms, the gate job EXACT six
seconds after submission, sixteen audit events verified under
`operator/audit_public_key.pem`; the whole guest script in 122.8 s.

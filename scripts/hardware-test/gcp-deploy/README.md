# gcp-deploy — the one-button deployment, on the record

[`deploy/gcp`](../../../deploy/gcp) is the button: `deploy.sh` verifies
the signed release, creates a Compute Engine Confidential VM (AMD SEV-SNP)
whose startup script stands the deployment up with `acpctl provision`,
starts both daemons as systemd services, gates a first genome and
verifies the audit log, and leaves the VM running. This kit runs it as a
newcomer would and then does what tells a deployment from a demo:

1. **a reset** — the VM reboots in place, on the same chip: both services
   come back on their own, the key files sealed to the chip open again,
   the worker's session opens again on the new boot;
2. **a second gate job** over ssh with `vg submit`, EXACT; `vg verify`
   replays the audit chain, which has grown across the reboot — one
   chain, every decision in order;
3. the VM is deleted, always, also on failure.

```bash
scripts/hardware-test/gcp-deploy/run.sh <project> [tag] [zone]   # ~12 min, one n2d-standard-4
```

What comes back (`evidence/<stamp>/`): `deploy/` — the record `deploy.sh`
keeps for a person (`deployment.txt`; `verify/` with `cosign.txt`,
`checksums.txt`, `slsa.txt`, `tag.txt`, `assets.sha256`, `tools.txt`;
`serial-console.txt`; `guest/` with the guest's own record under its
`sha256sums.txt`: `provision.json`, both identities, both configurations,
`sealed-files.txt`, `chip.txt`, `job.json`, `audit-verify.json`,
`audit-events.jsonl`, `audit-public-key.pem`, the units, the daemons'
logs and metrics, `steps.txt`, `timeline.txt`, the pip logs);
`deploy.out` (what the person saw, the `PROVEN` summary among it);
`after-reboot/` — `health.txt`, `journal-this-boot.txt`, `boots.txt`,
`submit.txt`, `status-live.txt`, `audit-verify.json`, `status.txt`,
`audit-events.jsonl`, `pause.txt` (the reads of the live segment pause
both services and start them again: ADR 0027, `vg verify | audit | events`);
`summary.txt`; `runner.log`; `sha256sums.txt`. Keys, seeds and the API
token stay on the VM and die with it.

Run on record: `evidence/20261028T130334Z/` (claim C55) — release
`v0.12.0` on an n2d-standard-4, Milan, in `us-central1-c`. `deploy.sh`
251 s from the command to the `PROVEN` summary: the tag's signature good,
the checksums list verified under `release.yml@refs/tags/v0.12.0`, 5 of 5
files on it, 5 of 5 SLSA provenances; on the guest 154 s — the runtime
46 s, `acpctl provision` 10.5 s (both measurements `9fc6d42b…b8cf` from
the chip, eight key files sealed to its derived key, the Milan chain from
KDS under the pinned ARK), the first genome 5 s, `sagvd` ready 13 s after
its start and the session open at once (handshake 231 ms, 7980 bytes of
evidence), the gate job EXACT 6 of 6 in 5.2 s, sixteen audit events
verified after a 3.7 s pause, both services back in 11 s. Then the reset:
ssh and the session back 87 s later — systemd started both units, the
worker dialled five times while `sagvd` opened its sealed key files and
its queue (one record, finished) and bound its listener, the session
opened on the new boot; `vg submit` over ssh gated a second job EXACT 6
of 6; `vg verify` replayed one chain of 32 events (16 before the reset).
The chip, as the authority's verifier read it: Milan, TCB snp 0x1f,
microcode 0xe1, firmware 1.58.3, alias check complete, above the floors
of AMD's bulletins (0x1b, 0xde).

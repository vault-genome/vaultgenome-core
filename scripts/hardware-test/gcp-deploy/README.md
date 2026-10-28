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
scripts/hardware-test/gcp-deploy/run.sh <project> [tag] [zone]          # ~12 min, one n2d-standard-4 (AMD SEV-SNP)
scripts/hardware-test/gcp-deploy/run.sh <project> [tag] [zone] tdx      # the same on a c3-standard-4 Intel TDX Trust Domain
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

On Intel TDX: `evidence/20261028T162741Z/` (claim C56) — a c3-standard-4
Trust Domain in `us-central1-c`. `deploy.sh --platform tdx` 287 s to
`PROVEN`: the guest installed the runtime (44 s) and `tpm2-tools`, then
rebooted once so the key files would be sealed on a settled boot; on
that boot `acpctl provision` 7.8 s (`provider=auto` resolved `gcp-tdx`,
both measurements SHA-384 over MRTD and RTMR0–3, eight key files sealed
to the vTPM), the first genome 8 s, `sagvd` ready 3 s after its start,
the session open 1 s after the worker's (the quote under the PCK chain
to Intel's root, Intel's TCB info for FMSPC `00806f050000` and QE
identity on the record), the gate EXACT 6 of 6 in 4.2 s, sixteen events
verified, the services back in 3 s — 29.8 s on the settled boot. After
the reset, the third boot: ssh and the session back 59 s later, the
second job EXACT 6 of 6, 32 events on one chain, `vg audit` and `vg
events` each pausing the services for about 3 s. The same day the kit
ran once more on SEV-SNP with the guest that knows both platforms
(`evidence/20261028T162801Z/`): 271 s to `PROVEN`, the same figures as
the first record, the second job EXACT, 32 events.
On `v0.13.0`, the release whose notes carry the button for its tag
(release procedure §5.9), both platforms again on 2026-10-28, within an
hour of the release: `evidence/20261028T214656Z/` — SEV-SNP, `deploy.sh`
267 s to `PROVEN` (the runtime 47.2 s, provision 10.5 s, `sagvd` ready
17 s after its start, the session open 0 s after the worker's, the gate
job EXACT in 5.2 s; 155.9 s on the guest), the reset and the services back
in 86 s, a second job EXACT over ssh, one chain of 32 events; the chip
Milan, TCB snp 0x1f, microcode 0xe1, above the floors.
`evidence/20261028T215508Z/` — TDX, `deploy.sh --platform tdx` 263 s to
`PROVEN` with the settled-boot reboot (on the settled boot: provision 8.2 s,
`sagvd` ready 3 s after its start, the session open 1 s after the
worker's, EXACT in 4.2 s, 30.3 s from its first command to the sealed
verdict), the reset and the services back in 58 s with the vTPM opening
the key files again, a second job EXACT, one chain of 32 events.


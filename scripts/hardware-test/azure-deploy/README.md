# azure-deploy — the one-button deployment on Azure, on the record

[`deploy/azure`](../../../deploy/azure) is the button: `deploy.sh`
verifies the signed release, deploys `azuredeploy.json` — one Azure
Confidential VM (AMD SEV-SNP) whose cloud-init script verifies the
release again on the guest, reboots once so the key files are sealed on a
settled boot, stands the deployment up with `acpctl provision`, starts
both daemons as systemd services, gates a first genome and verifies the
audit log — fetches the record over ssh and leaves the VM running. This
kit runs it as a newcomer would, into a resource group of its own, and
then does what tells a deployment from a demo:

1. **a restart** — a power cycle at the hypervisor: both services come
   back on their own, the vTPM opens the sealed key files again, the
   worker's session opens again on the new boot;
2. **a second gate job** over ssh with `vg submit`, EXACT; `vg verify`
   replays the audit chain, which has grown across the restart — one
   chain, every decision in order;
3. the resource group is deleted, always, also on failure.

```bash
scripts/hardware-test/azure-deploy/run.sh [tag] [location]   # ~15 min, one Standard_DC4as_v5 (West Europe by default)
```

It stops before spending anything when the committed `azuredeploy.json`
is not what `guest.sh` makes (`make-template.sh --check`).

What comes back (`evidence/<stamp>/`): `deploy/` — the record
`deploy.sh` keeps for a person (`deployment.txt`,
`deployment-outputs.json`; `verify/` with `cosign.txt`, `checksums.txt`,
`slsa.txt`, `tag.txt`, `assets.sha256`, `tools.txt`;
`serial-console.txt`; `guest/` with the guest's own record under its
`sha256sums.txt`: `guest-cosign.txt` and the checksums list as the guest
verified it, `vtpm.txt`, `provision.json` with both measurements and both
boots, the identities, the configurations, `sealed-files.txt`,
`chip.txt`, `job.json`, `audit-verify.json`, `audit-events.jsonl`,
`audit-public-key.pem`, the units, the daemons' logs and metrics,
`steps.txt`, `timeline.txt`, the pip logs); `deploy.out` (what the
person saw, the `PROVEN` summary among it); `after-restart/` —
`health.txt`, `journal-this-boot.txt`, `boots.txt`, `deploy-unit.txt`,
`submit.txt`, `status-live.txt`, `audit-verify.json`, `status.txt`,
`audit-events.jsonl`, `pause.txt`; `summary.txt`; `runner.log`;
`sha256sums.txt`. Keys, seeds and the API token stay on the VM and die
with it.

## Runs

| Release | Record | What it shows |
| - | - | - |
| `v0.13.0-rc1` (the rehearsal of 0.13.0; the first release whose `acpctl provision` writes the Azure families' quote and seal selection without PCR 10, ADR 0037 amendment of 2026-10-28) | [`evidence/20261028T205033Z-refused-host/`](evidence/20261028T205033Z-refused-host/) | The host Azure chose, a `Standard_DC4as_v5` in West Europe, ran SNP firmware 0x17, under the 0x1B floor of AMD-SB-3020 for Genoa: the verifier refused it at the handshake (`TCB floor: reported TCB snp 0x17 below 0x1b`, ADR 0033), the deployment stopped and the resource group was deleted. The guest and the kit name the refusal since this run; the kit deploys again on another host once. |
| `v0.13.0-rc1` | [`evidence/20261028T210406Z/`](evidence/20261028T210406Z/) | PASS on another host (Genoa, SNP 0x1C, microcode 0x58): the release verified here and on the guest, `PROVEN` 252 s after the command (the settled boot: provision 1.9 s, 19.8 s from its first command to the sealed verdict), both vTPMs quoting `sha256:0,1,2,3,4,5,6,7,8,9,11,12,13,14` (`provision.json`, `vtpm_pcrs`) and the key files sealed under the same; after `az vm restart` the services back on their own in 67 s, the sealed key files opened again, the worker's session opened on the new boot; a second job over ssh EXACT 6/6; the chain verified across the restart, 32 events (was 16). Across the restart only PCR 10 moved (`after-restart/pcrs-diff.txt`): IMA's, and no longer in the pin or the seal. |
| `v0.13.0` | [`evidence/20261028T214657Z-refused-host/`](evidence/20261028T214657Z-refused-host/) | The first host for the release's own run, again a `Standard_DC4as_v5` in West Europe on SNP firmware 0x17, refused by the verifier at the handshake (`TCB floor: reported TCB snp 0x17 below 0x1b`) — the second such host of the day. The kit's own retry did not run that time: under `set -e` the failing deploy pipeline ended the script before the refusal was read (fixed since: the pipeline is a condition). |
| `v0.13.0` | [`evidence/20261028T215840Z/`](evidence/20261028T215840Z/) | **Claim C57.** The first host (SNP firmware 0x17) refused by the verifier and named on the record (`refused-host.out`, `refused-host-record/`); the kit deployed again in a second resource group: Genoa, SNP 0x1C — `PROVEN` 293 s after the command (the settled boot: provision 2.3 s, 22.6 s from its first command to the sealed verdict), both sides quoting and sealing under `sha256:0-9,11-14`, the boot `dfc99de8…` pinned on both sides; after `az vm restart` the services back in 166 s, the key files opened again, a second job EXACT 6/6, one chain of 32 events; only PCR 10 moved across the restart. |
| `v0.14.0` | [`evidence/20261029T211713Z/`](evidence/20261029T211713Z/) | PASS, nine minutes after the release was published: a Genoa host (SNP 0x1C, microcode 0x58, above the floors), not refused; the release verified here and on the guest; `PROVEN` 310 s after the command (the settled boot: provision 2.3 s, 22.0 s from its first command to the sealed verdict), both sides quoting and sealing under `sha256:0-9,11-14`, the boot `02be54f2…` pinned on both sides; after `az vm restart` the services back in 122 s, the key files opened again, the session on the new boot; a second job EXACT 6/6; one chain of 32 events (was 16); only PCR 10 moved across the restart (`after-restart/pcrs-diff.txt`). |

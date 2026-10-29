# aws-deploy — the one-button deployment on AWS, on the record

[`deploy/aws`](../../../deploy/aws) is the button: `deploy.sh` verifies
the signed release, creates a CloudFormation stack from `template.json` —
one EC2 instance with AMD SEV-SNP enabled (shared tenancy; Canonical's
current Ubuntu 24.04 AMI) whose user-data script `guest.sh` verifies the
release again on the guest, reads the chip's first report (a VLEK's
signature, no CHIP_ID), stands the deployment up with `acpctl provision`
under the family `aws-sev-snp`, starts both daemons as systemd services,
gates a first genome and verifies the audit log — fetches the record over
ssh and leaves the instance running. This kit runs it as a newcomer
would, into a stack of its own, and then does what tells a deployment
from a demo, and what is EC2's own:

1. **a stop and a start** — on shared tenancy a move to another host:
   both services come back on their own, the key files sealed with the
   firmware's derived key open again (on EC2 the fleet's, KNOWN_ISSUES
   19), the worker's session opens again on the new boot — a new
   REPORT_ID, the same VLEK, the same launch measurement;
2. **a second gate job** over ssh with `vg submit`, EXACT; `vg verify`
   replays the audit chain, which has grown across the move — one chain,
   every decision in order;
3. **the launch measurement computed, not trusted**: AWS's published EC2
   UEFI (github.com/aws/uefi, the release and its SHA-256 pinned in
   `run.sh`) measured here with sev-snp-measure for the instance's vCPU
   count, equal to what the chip reported and both daemons pinned;
4. the stack is deleted, always, also on failure; the record is checked
   for anything that names the account — an ARN, an IAM unique id, the
   twelve digits — before it is kept.

```bash
scripts/hardware-test/aws-deploy/run.sh [tag] [region] [instance-type] [--published BUCKET]   # ~8 min, one m6a.xlarge in us-east-2 by default
```

It stops before spending anything when the committed `template.json` is
not what `guest.sh` makes (`make-template.sh --check`); with
`--published BUCKET` it also checks that the template the button's link
serves is the committed one, byte for byte.

What comes back (`evidence/<stamp>/`): `deploy/` — the record `deploy.sh`
keeps for a person (`deployment.txt`, `deployment-outputs.json`; `verify/`
with `cosign.txt`, `checksums.txt`, `slsa.txt`, `tag.txt`, `assets.sha256`,
`tools.txt`; `serial-console.txt`, scrubbed of the account; `guest/` with
the guest's own record under its `sha256sums.txt`: `guest-cosign.txt` and
the checksums list as the guest verified it, `tsm.txt`, `dmi.txt`, the
probe — `probe-report.bin`, `probe-certs.bin` with the VLEK,
`probe-nonce.bin` — `provision.json` with both measurements and both
CSP_IDs, the VLEK chain, the identities, the configurations,
`sealed-files.txt`, `chip.txt`, `job.json`, `audit-verify.json`,
`audit-events.jsonl`, `audit-public-key.pem`, the units, the daemons' logs
and metrics, `steps.txt`, `timeline.txt`, the pip logs); `deploy.out`
(what the person saw, the `PROVEN` summary among it); `after-move/` —
`addresses.txt`, `identity.txt` (REPORT_ID, the VLEK and the measurement
before and after), `health.txt`, `journal-this-boot.txt`, `boots.txt`,
`host.txt`, `submit.txt`, `status-live.txt`, `audit-verify.json`,
`status.txt`, `audit-events.jsonl`, `chip.txt`, `pause.txt`;
`measurement.txt`; `summary.txt`; `stack-deleted.txt`; `runner.log`;
`sha256sums.txt`. Keys, seeds and the API token stay on the instance and
die with it.

## Runs

| Release | Record | What it shows |
| - | - | - |
| `v0.14.0-rc1` (the rehearsal of 0.14.0; the first release that carries the `aws-sev-snp` family) | [`evidence/20261029T201000Z/`](evidence/20261029T201000Z/) | PASS: the release verified here (5 of 5 files on the signed list, 5 of 5 provenances, the tag) and on the guest (`Verified OK`, the same list); `PROVEN` 290 s after the command — on the guest 160.1 s from its first command to the verified audit log: the chip's first report signed by a VLEK with no CHIP_ID, `provision` 0.38 s with both sides `auto` → `aws-sev-snp`, both `vlek_csp_id` `CN=cc-us-east-2.amazonaws.com`, eight key files sealed with `sev-snp-derived-key`, the session opened 3.0 s after the services started on the family's envelope, the gate job EXACT 6/6 in 8.6 s, sixteen audit events verified; the record: Milan, `signing_key vlek`, REPORT_ID `621962de…`, TCB 0x1f/0xe1, firmware 1.58.3, the VLEK `65d5b55b…` valid to 2027-10-01. The stop and start: stopped in 32 s, running again on a new address 18 s later, both services back with the sealed key files opened and the session on the new boot 87 s after the stop; a second job EXACT 6/6; one chain of 32 events (was 16); a new REPORT_ID `83403848…`, the same VLEK, the same measurement `1d8ee9ba…`, which is sev-snp-measure 0.0.13 over AWS's UEFI 20260814 for 4 vCPUs. Two runs before it the same evening, with every line of the hardware green, are not on the record: the first because the kit's own check refused a record that named the account (the image's SSM agent prints its refusal with an ARN on the serial console; `deploy.sh` scrubs the console copy since), the second because the kit read the measurement after the move under the wrong key and did not compare it (it does now). |
| `v0.14.0` | [`evidence/20261029T211714Z/`](evidence/20261029T211714Z/) | **Claim C59.** Nine minutes after the release was published: the published template equal to the committed one; the release verified here (5 of 5 files, 5 of 5 provenances, the tag) and on the guest (`Verified OK`, the same list, 5 of 5 files); `PROVEN` 328 s after the command, 184.2 s on the guest — the first report under a VLEK with no CHIP_ID, `provision` 0.51 s with both sides `auto` → `aws-sev-snp` and both CSP_IDs `CN=cc-us-east-2.amazonaws.com`, eight key files sealed with the derived key, the session 3.3 s after the services started, the gate EXACT 6/6 in 8.7 s, sixteen events verified; Milan 0x1f/0xe1, firmware 1.58.3, REPORT_ID `ff13b2ee…`, the VLEK `65d5b55b…` valid to 2027-10-01. Stopped in 33 s, on a new address 18 s later, both services back with the sealed key files opened and the session on the new boot 82 s after the stop; a second job EXACT 6/6; one chain of 32 events; a new REPORT_ID `cec18f74…`, the same VLEK, the same measurement `1d8ee9ba…` = sev-snp-measure 0.0.13 over AWS's UEFI 20260814 for 4 vCPUs; nothing on the record names the account; the stack deleted. |

The family's first capture and the kit that proves it from the tree's
binaries: [`../aws-sev-snp`](../aws-sev-snp) (C58). The runbook:
[`docs/operator/runbooks/real-tee-aws-sev-snp.md`](../../../docs/operator/runbooks/real-tee-aws-sev-snp.md).

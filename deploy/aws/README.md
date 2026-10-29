# One button on AWS

[![Launch Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://us-east-2.console.aws.amazon.com/cloudformation/home?region=us-east-2#/stacks/create/review?templateURL=https://s3.us-east-2.amazonaws.com/vaultgenome-deploy/template.json&stackName=vaultgenome)

A Vault Genome deployment on one EC2 instance with AMD SEV-SNP (shared
tenancy, `m6a.xlarge`) from the signed release, proven the way the
project's reference deployment is proven, and left running. The button
opens the CloudFormation console on [`template.json`](template.json): your
ssh public key, the release tag — and the instance stands itself up. From
a laptop with `aws` signed in, the same template with the record brought
back to you:

```bash
deploy/aws/deploy.sh                                      # the latest release; --tag v0.14.0 for one
deploy/aws/deploy.sh --region eu-west-1 --type c6a.xlarge
deploy/aws/destroy.sh --region eu-west-1                  # the stack: the instance, its disk, the key pair, the security group
```

| What | Where |
| - | - |
| The release verified on the machine that deploys it: the signed checksums list under the release workflow's identity for the tag (cosign), the five files against the list, their SLSA provenance against the source tag, the tag's signature against the keys pinned on `main` | [`deploy.sh`](deploy.sh) step 2, [`../lib/verify-release.sh`](../lib/verify-release.sh) |
| One stack — a key pair from your public key, a security group with port 22 open to the deployer's address, a launch template with `AmdSevSnp` enabled and `guest.sh` as the user data (gzip: EC2 holds user data to 16 KB), one instance from Canonical's current Ubuntu 24.04 AMI (read from AWS's public SSM parameter; UEFI; configfs-tsm in the kernel), a 32 GB encrypted disk; the list's SHA-256 and the record's stamp in the instance's tags, which the guest reads from the instance metadata | [`template.json`](template.json), made from `guest.sh` by [`make-template.sh`](make-template.sh) |
| **The guest verifies the release itself** — the button may have been pressed in the console with no machine of yours in the loop: the signed list under the release identity (cosign at a pinned hash), the same list `deploy.sh` verified when it ran, the five files against it | [`guest.sh`](guest.sh) step 1 |
| The chip's first report through configfs-tsm — signed by the provider's **VLEK** (FLAGS.SIGNING_KEY = 1), no CHIP_ID, the certificate table beside it — and the chip's product from the report's CPUID; an instance whose reports a VCEK signs (a Dedicated Host) or without SEV-SNP stops here by name | `guest.sh` step 2 |
| `acpctl provision --provider auto`: the family `aws-sev-snp` resolved from the host (configfs-tsm says `sev_guest`, the DMI vendor says Amazon EC2), the product's VLEK chain (ASVK and ARK) from AMD KDS verified against the pinned roots, the launch measurement — AWS's published UEFI measured for the vCPU count — and the VLEK's CSP_ID pinned on both sides, every key file sealed with the firmware's derived key; a first genome made and sealed; both daemons as `systemd` services; a gate job EXACT over the Return Path; the audit log verified under the operator's key | `guest.sh` steps 4–5 |
| The record over ssh (or from the serial console), the summary that begins with `PROVEN`; the same block printed by the guest on the serial console, for `aws ec2 get-console-output --latest` | [`deploy.sh`](deploy.sh) steps 5–6 |

About USD 0.19 an hour while an `m6a.xlarge` runs in Ohio (the on-demand
rate plus AWS's 10 percent for SEV-SNP); about five minutes from the
command to the summary. SEV-SNP on shared tenancy is offered in US East
(Ohio) and Europe (Ireland), on `m6a`, `c6a` and `r6a`.

## From the console

The button asks for the stack's name, your ssh public key (one line), who
may reach port 22 (`0.0.0.0/0` lets anyone with the key; your own address
as `a.b.c.d/32` is tighter) and the release tag; the instance type and
the AMI have defaults. The stack is complete when the instance is up; the
guest is then still at work for about five minutes. Its proof appears in
the instance's **Monitor and troubleshoot → Get system log** (or
`aws ec2 get-console-output --instance-id <id> --latest --output text`)
between `===VG-PROVEN===` and `===VG-PROVEN-END===`, and the record is on
the instance under `/var/lib/vaultgenome/record/<stamp>/`. With `aws`
signed in, `deploy.sh --attach --stack <name>` waits for it and brings
the record here.

The link behind the button reads the template from an S3 bucket a
maintainer publishes it to (the CloudFormation console takes a template
from S3 only): [`publish-template.sh`](publish-template.sh) uploads the
committed `template.json` and checks that the bucket serves it byte for
byte; `publish-template.sh --check` is the same check from anywhere, and
the kit runs it. The deployer's identity needs the actions in
[`deployer-policy.json`](deployer-policy.json): the stack, the instance
and its launch template, the key pair, the security group, the console
output, and the public SSM parameter that names Canonical's AMI. A maintainer who publishes the
template needs [`publisher-policy.json`](publisher-policy.json) as well:
the bucket and its `template*.json` objects, nothing else.

## What it is, and what it is not

- **The reference deployment, kept running.** What
  [`scripts/hardware-test/aws-sev-snp`](../../scripts/hardware-test/aws-sev-snp)
  proves on one EC2 instance (C58) — then not stopped: `sagvd.service`
  and `acp-compute.service`, their state under `/var/lib/vaultgenome`,
  the deployment under `/etc/vaultgenome` (root, 0700), the binaries
  under `/opt/vaultgenome/bin` with `vg`, the operator's hand on the
  host: `vg health | status | logs | submit | job` live, and `vg verify |
  audit | events` for the audit log, which pause both services for about
  fifteen seconds (ADR 0027).
- **The provider's key, not a chip's.** On EC2 the report is signed by
  the VLEK AMD issues to AWS for the product line and TCB, the same
  certificate across a region's fleet, and CHIP_ID is zero: the policy
  pins the provider's CSP_ID (`CN=cc-us-east-2.amazonaws.com` for Ohio),
  not a machine; the launch measurement is AWS's published UEFI measured
  for the vCPU count, which the
  [runbook](../../docs/operator/runbooks/real-tee-aws-sev-snp.md) shows
  how to compute (ADR 0038).
- **The fleet's sealing key.** The key files are sealed with the
  firmware's derived key, which on EC2 is the same for every SEV-SNP guest
  of the same launch measurement and guest policy: they open again after a
  stop/start that moves the instance to another host — and they would open
  on any such guest (KNOWN_ISSUES 19). No vTPM is combined with the family
  in this build, so the boot after AWS's UEFI is not pinned; a customer
  who needs a machine or a boot pinned has the Google Cloud and Azure
  buttons for that.
- **One host.** Both daemons on one instance; the two-host form is three
  commands of `acpctl provision` (ADR 0028, C39).
- **The network.** Every Vault Genome listener binds loopback; the
  operator reaches them over ssh. The instance has a public address for
  its own fetches (GitHub, PyPI, AMD KDS, Ubuntu's archive) and for ssh;
  a stop/start gives it a new one (`aws ec2 describe-instances`).
- **Nothing is sent anywhere.** The record is fetched over ssh by the
  machine that ran `deploy.sh`, or read from the instance's serial
  console; keys, seeds and the API token never leave the instance and
  are never printed. No IAM role is attached to the instance, and nothing
  on the record names the account.

## The record

`records/<stamp>/` beside this script: `deployment.txt`,
`deployment-outputs.json`, `verify/`, `serial-console.txt`, and `guest/`
— the guest's own record under its `sha256sums.txt`: `guest-cosign.txt`
and `checksums-<tag>.txt` (the list as the guest verified it), `tsm.txt`,
`dmi.txt`, the probe (`probe-report.bin`, the chip's first report;
`probe-certs.bin`, the certificate table with the VLEK), `provision.json`
(both measurements, both CSP_IDs), the VLEK chain, identities,
configurations (paths, no secret), `sealed-files.txt`, `chip.txt`,
`job.json`, `audit-verify.json`, `audit-events.jsonl`,
`audit-public-key.pem`, the units, the daemons' logs and metrics,
`steps.txt`, `timeline.txt`, the pip logs.

Needs: `aws` signed in, `curl`, `git`, `python3`, `ssh` and `scp`;
`cosign` and `slsa-verifier` on PATH, or on Linux x86-64 they are fetched
at pinned hashes. The account needs EC2 in a region that offers SEV-SNP
and the vCPU quota for the instance type (an `m6a.xlarge` is 4).

## When the host AWS chose is refused

The verifier holds the chip to AMD's bulletin level (ADR 0033): a host
whose SNP firmware or microcode is below the floor for its product is
refused at the handshake, and the guest's record says so —
`REFUSED by the verifier, not by this deployment: … TCB floor …`. The
host is AWS's choice, not the template's: stop and start the instance (it
moves to another host) or deploy again. The three hosts captured on
2026-10-29 in Ohio and the kit's hosts all ran SNP firmware 0x1F,
microcode 0xE1, above the floors.

## On the record

The kit [`scripts/hardware-test/aws-deploy`](../../scripts/hardware-test/aws-deploy)
runs `deploy.sh` as a newcomer would, then stops and starts the instance
— a move to another host — and shows the services back, the sealed key
files opened again under the fleet's key, a second job EXACT and the audit
chain grown across the move, and deletes the stack. Its records are under
`scripts/hardware-test/aws-deploy/evidence/`.

# Runbook: AWS EC2 on AMD SEV-SNP (`aws-sev-snp`)

An EC2 instance with AMD SEV-SNP — `m6a`, `c6a` or `r6a`, launched with
`--cpu-options AmdSevSnp=enabled` in a region that offers it (US East (Ohio),
Europe (Ireland)) — runs the daemons as a family of its own, `aws-sev-snp`
(ADR 0038). What is the same as on Compute Engine: the report comes through
configfs-tsm, the policy is the attack record of ADR 0033, the root is the
AMD root this build pins (ADR 0024), the key files are sealed with the
firmware's derived key. What is different, and what this runbook is about:

| | Compute Engine (`gcp-sev-snp`) | EC2 (`aws-sev-snp`) |
|---|---|---|
| The report's signer | the chip's VCEK, fetched from AMD KDS by CHIP_ID and TCB | the provider's **VLEK** (FLAGS.SIGNING_KEY = 1), shown by the host in the certificate table beside the report and carried inside the evidence; KDS does not serve it |
| The chain | `/vcek/v1/<product>/cert_chain` (ASK + ARK) | `/vlek/v1/<product>/cert_chain` (**ASVK** + ARK): `acpctl tee fetch-amd-chain --signer vlek` |
| The machine's identity | CHIP_ID, pinnable (`sev_snp.chip_ids`) | **none** — CHIP_ID is zero; the policy pins the provider instead (`tee.peer.csp_ids`, the VLEK's CSP_ID, e.g. `CN=cc-us-east-2.amazonaws.com`); REPORT_ID is on the record per boot |
| The launch measurement | Google's UEFI per vCPU count (ADR 0037) | AWS's published UEFI per vCPU count, computable from the binary (below) |
| The sealing key | the chip's derived key: one machine | the firmware's derived key is **the fleet's**: a file opens on any EC2 SEV-SNP guest of the same launch measurement and guest policy; it survives a stop/start |
| A vTPM | yes (`gcp-sev-snp-vtpm`, `tee.sealer both`) | not in this build: `tee.sealer tpm2` and `both` are refused |

## 1. The instance

```bash
AMI=$(aws ssm get-parameter --region us-east-2 --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text)
aws ec2 run-instances --region us-east-2 --image-id "$AMI" --instance-type m6a.xlarge --cpu-options AmdSevSnp=enabled \
  --key-name <your key pair> --security-group-ids <ssh from your address> --associate-public-ip-address
```

Ubuntu 24.04's kernel (7.0 on the AMI of 2026-10-23) has configfs-tsm and
the sev-guest driver; Amazon Linux 2023 needs its kernel-6.12 variant
(configfs-tsm is Linux 6.7 or later). On the guest:

```bash
sudo mount -t configfs none /sys/kernel/config 2>/dev/null; ls /sys/kernel/config/tsm/report   # present
cat /sys/class/dmi/id/sys_vendor                                                             # Amazon EC2
```

`tee.provider: auto` resolves to `aws-sev-snp` from exactly these two facts:
configfs-tsm serves `sev_guest`, and the machine's DMI vendor is Amazon EC2
(`provider_auto.go`). A report signed by the VCEK on a host whose vendor says
EC2 is refused by the producer at start, by name.

## 2. One command

```bash
acpctl provision --out /etc/vaultgenome --bin-dir /opt/vaultgenome/bin --provider auto --fetch-amd-chain milan \
  --door-python /opt/vaultgenome/venv/bin/python3 --base-model /opt/vaultgenome/base --worker-package /opt/vaultgenome/worker/genome
```

`--fetch-amd-chain milan` fetches the **VLEK** chain for an `aws-sev-snp`
worker (the family decides the signer); `provision.json` records
`amd_cert_chain` (`amd-milan-vlek-cert_chain.pem`), both sides' `vlek_csp_id`
(from each daemon's identity, `aws_sev_snp.csp_id`), the sealer
(`sev-snp-derived-key`) and the measurements. Two hosts (ADR 0028): the
worker's bundle carries the authority's CSP_ID and the worker pins it
(`tee.peer.csp_ids`); pin the worker's on the authority after `pin-worker`
prints it — the daemons accept any VLEK that chains to AMD's root until then,
and record whose it was.

What the daemons refuse in an `aws-sev-snp` configuration, at start:
`sev_snp.chip_ids` (no chip to name), `vcek_cache_dir` and `amd_kds_url`
(no VCEK, no KDS at verification), a VCEK (ASK) chain in
`amd_cert_chain_path`, `tee.sealer tpm2`/`both`, a delegated
`tee.peer.verifier` (the delegated Verifiers do not read the VLEK beside
the report yet).

## 3. The launch measurement, computed rather than trusted

The chip reports AWS's published EC2 SEV-SNP UEFI (github.com/aws/uefi)
measured for the instance's vCPU count. The pin `provision` took from the
first report can be checked against the publication:

```bash
curl -fsSLO https://github.com/aws/uefi/releases/download/20260814/ovmf_img.fd
sha256sum ovmf_img.fd        # 67aaae01a6f4245cc071e008859b00ea2b5c05824362c41d165c3b4751372bc9 (release 20260814)
pip install sev-snp-measure==0.0.13
sev-snp-measure --mode snp --vcpus 4 --vmm-type ec2 --ovmf ovmf_img.fd    # m6a.xlarge: 1d8ee9bae96e2b88…
sev-snp-measure --mode snp --vcpus 2 --vmm-type ec2 --ovmf ovmf_img.fd    # m6a.large:  7a89cceaaba0bbdd…
```

A new AWS UEFI release is a new measurement: compute it from the new
binary and add it to the policy before the fleet moves. The operating
system on the disk is not in the measurement (ADR 0037's finding holds
here too) and this build offers no vTPM on EC2 to pin the boot with.

## 4. What the record says

The admission record (`TRUST_EVALUATED`, `peer_detail.sev_snp`) carries,
beside the chip's TCB and the floors it was held to: `signing_key: vlek`,
`report_id_hex` (the firmware's identity for this guest, this boot),
`chip_id_hex` (all zero), and `vlek` — `csp_id`, `product_name`, `tcb`,
`not_before`/`not_after`, `sha256`. `sagvd identity` and `acp-compute
identity` print `aws_sev_snp.csp_id` for the pin.

## 5. The kit

`scripts/hardware-test/aws-sev-snp/run.sh [region] [instance-type]` does
all of the above on a fresh instance from this tree's binaries, checks every
line (the family resolved, the sealer, both CSP_IDs, the probe's signer,
the gate EXACT, the audit log verified, the admission record, eight sealed
files naming `aws-sev-snp`), holds the measurement against the published
UEFI, and terminates the instance, the key pair and the security group —
always. Its evidence sits under `scripts/hardware-test/aws-sev-snp/evidence/`;
the run of 2026-10-29 on an `m6a.xlarge` is claim C58 (`PASS`, 141 s on the
guest from the first command to the verified audit log).

The first capture of the family — three instances, their reports, the
certificate tables, the VLEK, AMD's chains, the derived keys across a
reboot and two stop/starts — is `internal/shared/tee/testdata/aws-sev-snp/20261029T155800Z/`
(`CAPTURE.md`).

## 6. Day 2

- **Stop/start** moves the instance to another host; the key files open
  there (the derived key is the fleet's). A **reboot** keeps the host. The
  VLEK is valid to a date (`vlek_not_after` on the record): AWS loads a new
  one before then; nothing changes on your side — the policy pins the
  provider, not the certificate.
- **A TCB change** (AMD firmware, microcode) is a new VLEK from AWS and a
  new reported TCB; the floors of ADR 0033 apply as everywhere.
- **Another region** is another CSP_ID (`CN=cc-<region>.amazonaws.com`):
  add it to `csp_ids` before a peer there is admitted.

# One button on Azure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fvault-genome%2Fvaultgenome-core%2Fmain%2Fdeploy%2Fazure%2Fazuredeploy.json)

A Vault Genome deployment on one Azure Confidential VM (AMD SEV-SNP,
`Standard_DC4as_v5`) from the signed release, proven the way the project's
reference deployment is proven, and left running. The button opens the
portal on [`azuredeploy.json`](azuredeploy.json): a resource group, your
ssh public key, the release tag — and the VM stands itself up. From a
laptop with `az` signed in, the same template with the record brought
back to you:

```bash
deploy/azure/deploy.sh                                    # the latest release; --tag v0.14.0 for one
deploy/azure/deploy.sh --resource-group rg --location eastus
deploy/azure/destroy.sh --resource-group rg               # the VM and its resources, nothing else
```

| What | Where |
| - | - |
| The release verified on the machine that deploys it: the signed checksums list under the release workflow's identity for the tag (cosign), the five files against the list, their SLSA provenance against the source tag (slsa-verifier), the tag's signature against the keys pinned on `main` | [`deploy.sh`](deploy.sh) §2, [`../lib/verify-release.sh`](../lib/verify-release.sh), `records/<stamp>/verify/` |
| One Confidential VM — secure boot, vTPM, the OS disk encrypted with the VM guest state, Ubuntu 24.04 CVM image — with `guest.sh` as its cloud-init script, port 22 open to the deployer's address, the list's SHA-256 in its tags | [`azuredeploy.json`](azuredeploy.json), made from [`guest.sh`](guest.sh) by [`make-template.sh`](make-template.sh) |
| **The guest verifies the release itself** — the button may have been pressed in the portal with no machine of yours in the loop: the signed list under the release identity (cosign at a pinned hash), the same list the deployer verified when `deploy.sh` ran, the five files against it | [`guest.sh`](guest.sh) step 1, `guest/guest-cosign.txt`, `guest/checksums-check.txt` |
| The chip's product (Milan or Genoa) read from the SEV-SNP report in the vTPM's HCL report; `tpm2-tools`; the worker runtime from the hash-pinned locks; **one reboot**, so the key files are sealed on a settled boot; `acpctl provision --provider auto` (azure-sev-snp from the HCL report; the AMD chain from KDS; both launch measurements and both boots pinned; every key file sealed to the vTPM); a first genome; both daemons as services; a gate job; the audit log verified | [`guest.sh`](guest.sh), `records/<stamp>/guest/` |
| The record over ssh (or from the serial console), the summary that begins with `PROVEN`; the same block printed by the guest on the serial console, for the portal's boot diagnostics | [`deploy.sh`](deploy.sh) §5–6 |

About USD 0.21 an hour while the VM runs in West Europe (0.17 in East
US — Azure's DC4as v5 price); about six minutes from the command to the
summary, one of them the reboot.

## From the portal

The button asks for a resource group, a region with the DCasv5 series
(West Europe, East US), your ssh public key and the release tag; `*` for
`sshSourcePrefix` lets anyone with the key reach port 22 — your own
address as `a.b.c.d/32` is tighter. When the deployment is done the VM is
still at work for about five minutes; its proof appears in the VM's
**Boot diagnostics → Serial log** between `===VG-PROVEN===` and
`===VG-PROVEN-END===`, and the record is on the VM under
`/var/lib/vaultgenome/record/<stamp>/`. With `az` signed in,
`deploy.sh --attach --resource-group <rg>` waits for it and brings the
record here.

## What it is, and what it is not

- **The reference deployment, kept running.** What
  [`scripts/hardware-test/azure-sev-snp/returnpath-e2e`](../../scripts/hardware-test/azure-sev-snp/returnpath-e2e)
  proves on one Azure CVM and
  [`provision-two-hosts`](../../scripts/hardware-test/provision-two-hosts)
  stood up with `acpctl provision` across two clouds (C36, C39, C54) —
  then not stopped: `sagvd.service` and `acp-compute.service`, their
  state under `/var/lib/vaultgenome`, the deployment under
  `/etc/vaultgenome` (root, 0700), the binaries under
  `/opt/vaultgenome/bin` with `vg`, the operator's hand on the host:
  `vg health | status | logs | submit | job` live, and `vg verify | audit
  | events` for the audit log, which pause both services for about
  fifteen seconds (ADR 0027).
- **The paravisor's measurement, the vTPM's boot.** On Azure the chip's
  launch measurement covers the paravisor and the firmware Azure
  measures, the same for every VM of the generation; the OS is in the
  vTPM's PCRs, which the quote records and the peer pins (ADR 0037, C54).
  The key files are sealed to the vTPM under this boot's PCRs: a reboot
  of the same image opens them, a new kernel does not; the
  [runbook](../../docs/operator/runbooks/real-tee-azure-sev-snp.md)
  says what a new image means for the pin. One rule the guest follows
  and the runbook states: systemd extends PCR 11 with the boot's phases,
  so the sealing runs after `systemd-pcrphase.service` and the daemons'
  units start after it too — a file sealed in one phase opens only in
  that phase.
- **One host.** Both daemons on one VM; the two-host form is three
  commands of `acpctl provision` (ADR 0028, C39).
- **The network.** Every Vault Genome listener binds loopback; the
  operator reaches them over ssh. The VM has a public address for its own
  fetches (GitHub, PyPI, AMD KDS) and for ssh.
- **Nothing is sent anywhere.** The record is fetched over ssh by the
  machine that ran `deploy.sh`, or read from the VM's serial console;
  keys, seeds and the API token never leave the VM and are never printed.

## The record

`records/<stamp>/` beside this script: `deployment.txt`,
`deployment-outputs.json`, `verify/`, `serial-console.txt`, and `guest/`
— the guest's own record under its `sha256sums.txt`: `guest-cosign.txt`
and `checksums-<tag>.txt` (the list as the guest verified it),
`vtpm.txt`, `provision.json` (both measurements and both boots),
identities, configurations (paths, no secret), `sealed-files.txt`,
`chip.txt`, `job.json`, `audit-verify.json`, `audit-events.jsonl`,
`audit-public-key.pem`, the units, the daemons' logs and metrics,
`steps.txt`, `timeline.txt`, the pip logs.

Needs: `az` signed in, `curl`, `git`, `python3`, `ssh` and `scp`;
`cosign` and `slsa-verifier` on PATH, or on Linux x86-64 they are
fetched at pinned hashes. The subscription needs quota for the
`standardDCASv5Family` in the region (the default 16 vCPUs is enough).

## When the host Azure chose is refused

The verifier holds the chip to AMD's bulletin level (ADR 0033): a host
whose SNP firmware or microcode is below the floor for its product is
refused at the handshake, and the guest's record says so —
`REFUSED by the verifier, not by this deployment: … TCB floor: reported
TCB snp 0x17 below 0x1b …`. The host is Azure's choice, not the
template's: on 2026-10-28 three of four `Standard_DC4as_v5` in West
Europe ran SNP firmware 0x1C and one ran 0x17. Run `destroy.sh` and
deploy again; the next host is usually current. The kit
(`scripts/hardware-test/azure-deploy`) does the same once, in a second
resource group, and keeps the refusal on its record (`refused-host.out`).

## On the record

Claim [C57](../../VERIFIABLE-CLAIMS.md#c57): on `v0.13.0`, 2026-10-28,
`scripts/hardware-test/azure-deploy/run.sh v0.13.0 westeurope` — the
release verified, the first host refused by the verifier (chip firmware
under AMD's floor) and named, the deployment on the next host `PROVEN`
293 s after the command (2.3 s to provision on the settled boot), both
sides quoting and sealing under the vTPM's PCRs without IMA's PCR 10; after
`az vm restart` both services back on their own, the sealed key files
opened again, a second job EXACT 6/6, one audit chain of 32 events. The
rehearsal `v0.13.0-rc1` did the same the same day. Records under
`scripts/hardware-test/azure-deploy/evidence/`.


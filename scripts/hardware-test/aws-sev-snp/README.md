# aws-sev-snp — the `aws-sev-snp` family on a real EC2 instance, on the record

An EC2 instance with AMD SEV-SNP (`--cpu-options AmdSevSnp=enabled`) signs
its reports with the provider's **VLEK**, not the chip's VCEK, names no
chip, and hands the VLEK out in the certificate table beside the report
([ADR 0038](../../../docs/adr/0038-ec2-sev-snp-under-a-vlek.md)). This kit
runs the daemons there from this tree's binaries and checks every line of
what that family is supposed to do:

1. **the instance** — one `m6a.xlarge` (AMD Milan, 4 vCPUs) from
   Canonical's current Ubuntu 24.04 AMI, under a key pair and a security
   group made for the run; `guest.sh` goes over as root;
2. **the host as the guest sees it** — configfs-tsm's first report
   (FLAGS.SIGNING_KEY = 1, CHIP_ID zero) and the certificate table beside
   it, the DMI vendor (`Amazon EC2`), the kernel, the worker runtime from
   the hash-pinned locks;
3. **one command** — `acpctl provision --provider auto --fetch-amd-chain
   milan --sealer auto`: both sides keep `tee.provider auto` and resolve
   the peer to `aws-sev-snp` from the host; the VLEK chain (ASVK + ARK)
   comes from AMD KDS and is held to the pinned root; each side's identity
   carries `aws_sev_snp.csp_id`, which the other side pins; eight key files
   are sealed with the firmware's derived key, each header naming the
   family;
4. **a real fine-tune** — a tiny base model built on the guest, a LoRA
   adapter trained on it and sealed;
5. **both daemons on what provision wrote** — the session opened on the
   family's envelope (the report and the VLEK), a gate job over the
   Return Path EXACT, both stopped, the audit log verified with the key
   provision kept for the operator; the admission record read back
   (`signing_key`, `report_id_hex`, the VLEK's CSP_ID and validity, the
   TCB and the floors, `chip_id_hex` all zero);
6. **the launch measurement, computed rather than trusted** — on the
   machine that ran the command, AWS's published EC2 UEFI (release
   20260814, its sha256 pinned in `run.sh`) measured with sev-snp-measure
   for the instance's vCPU count and compared with what the chip reported
   and both daemons pinned;
7. the instance, the key pair and the security group are terminated,
   always, also on failure.

```bash
scripts/hardware-test/aws-sev-snp/run.sh [region] [instance-type]   # us-east-2 m6a.xlarge by default; ~4 min; the instance is deleted at the end
```

It needs `aws` signed in to an account with EC2 in a region that offers
SEV-SNP (US East (Ohio), Europe (Ireland)), `go` for the binaries, and
`python3` with `pip` for sev-snp-measure.

What comes back (`evidence/<stamp>/`): `binaries.sha256` and `code-rev.txt`
(what ran and from which tree), `instance.json`, `guest.out` (what the
person saw), `guest/` — the guest's own record under its `sha256sums.txt`:
`dmi.txt`, `kernel.txt`, `tsm.txt`, `metadata.txt`, `probe-report.bin`,
`probe-certs.bin`, `probe-nonce.bin`, `probe-attrs.txt`, `provision.out`,
`provision.json`, `amd-milan-vlek-cert_chain.pem`, both identities, both
configurations (paths, no secret), `sealed-files.txt`, `finetune.json`,
`seal.json`, `sagvd.log`, `acp-compute.log`, both metrics, `job.json`,
`chip.txt`, `audit-verify.json`, `audit-events.jsonl`,
`audit-public-key.pem`, `steps.txt`, `timeline.txt`, `console.log`, the
pip logs — then `measurement.txt`, `vm-deleted.txt`, `runner.log`,
`sha256sums.txt`. Keys, seeds and the API token stay on the instance and
die with it. No IAM role is attached to the instance and no AWS
identifier that encodes the account is on the record.

## Runs

| Tree | Record | What it shows |
| - | - | - |
| `460db390` (`main` after #209) with the `aws-sev-snp` family of ADR 0038, not yet committed when it ran (the binaries report `460db390d22c-dirty`) | [`evidence/20261029T164825Z/`](evidence/20261029T164825Z/) | **Claim C58.** `PASS` 222 s after the command; 140.6 s on the guest from its first command to the verified audit log. `provision` 0.41 s: both sides `auto` → `aws-sev-snp` (`resolved_from: sev_guest (Amazon EC2)` in both logs), the VLEK chain from KDS under the pinned ARK `69d063b4…40bcd`, both sides' `vlek_csp_id` `CN=cc-us-east-2.amazonaws.com`, eight key files sealed with `sev-snp-derived-key`, each header `tee: aws-sev-snp`. The session opened 1.2 s after `sagvd` started on the family's envelope (3402 bytes, handshake 49 ms); the gate job EXACT 6/6, `max_abs_err` 0, 7.3 s; sixteen audit events verified, `ok: true`. The record: Milan, `signing_key: vlek`, REPORT_ID `53d72f8a…6331`, the VLEK `SEV-VLEK` issued by `SEV-VLEK-Milan` with TCB (4, 0, 0x1f, 0xe1) equal to the chip's reported TCB, valid 2026-10-01 to 2027-10-01 — the same certificate the morning's three captured hosts showed (`65d5b55b…0f4f`), `chip_id_hex` all zero; firmware 1.58.3, mitigation vector 0xfef, alias check complete, above the floors (0x1b, 0xde). The launch measurement `1d8ee9ba…cb5b` equal to sev-snp-measure 0.0.13 over AWS's UEFI 20260814 (`67aaae01…2bc9`) for 4 vCPUs. The kit's run before it that day stopped at the kit's own check — it expected `provider=aws-sev-snp` in `provision.json`, which rightly records `auto` with the peer resolved — fixed here, every line of the hardware green, and not on the record. |

The capture the family was written from — three instances, their
reports, the certificate tables, the VLEK, AMD's chains, the derived keys
across a reboot and two stop/starts — is
[`internal/shared/tee/testdata/aws-sev-snp/20261029T155800Z/`](../../../internal/shared/tee/testdata/aws-sev-snp/20261029T155800Z/CAPTURE.md).
The runbook:
[`docs/operator/runbooks/real-tee-aws-sev-snp.md`](../../../docs/operator/runbooks/real-tee-aws-sev-snp.md).

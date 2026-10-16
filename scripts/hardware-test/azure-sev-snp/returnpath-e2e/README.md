# returnpath-e2e — the Return Path on an Azure SEV-SNP Confidential VM

The twin of `../../gcp-sev-snp/returnpath-e2e/` for the `azure-sev-snp`
family (ADR 0025, plan item 4): one `Standard_DC4as_v5` Confidential VM
(Ubuntu 24.04, secure boot and vTPM) in West Europe, created by `run.sh`
with `az`, on which `cvm-returnpath-azure.sh` runs as root over ssh. Both
daemons attest with the chip's SEV-SNP report from the vTPM's HCL report,
bound to each handshake's challenge by a TPM quote under the vTPM's
attestation key — the Azure guest has no `/dev/sev-guest` — and each pins
the other's launch measurement; the chip's product (Milan or Genoa) is
read from the report and the matching AMD chain fetched from KDS and
verified against the pinned roots; every key file is sealed to the vTPM.
Then as on GCP: the real `vg_genome` worker fine-tunes a genome on the
guest, `acpctl` seals it, a rogue with the sealed key files off this vTPM
cannot open them, a rogue with the plaintext copies and another
attestation is refused at the handshake on the record, the gate job goes
over the Return Path and comes back EXACT, and the audit log verifies
under the published key.

```bash
scripts/hardware-test/azure-sev-snp/returnpath-e2e/run.sh [resource-group] [location]   # ~15 min, one DC4as_v5
```

The results come back as `evidence/<stamp>/`: `steps.txt`, `vtpm.txt`,
`product.txt`, the identities (with `vtpm.pcr_digest_hex`), the sealed
files' shapes, `seal.json`, the two rogues' logs, `job.json` and the gate
verdict, the daemons' logs and metrics, `audit-verify.json`,
`audit-events.jsonl`, `audit-public-key.pem`, `sha256sums.txt`; the
runner adds `runner-guest.log`. The capture kit that preceded the provider
is the parent directory (`../README.md`: the HCL report's layout and the
REPORT_DATA binding).

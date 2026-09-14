# Runbook: real AMD SEV-SNP attestation (production TEE mode)

By default the platform runs with the **simulated** TEE backend
(`ProviderSimulated`) — no hardware, good for local testing and the
`cmd/acp-demo` walkthrough. This runbook brings up **real AMD SEV-SNP**
attestation on a confidential VM, on either **GCP** or **Azure** — both proven
end to end and chained to the AMD root of trust (`ADR 0007`, `0009`;
`internal/shared/tee/{gcp,azure}_sev_snp_verify*.go`).

The verify path is identical for both clouds: parse the 1184-byte SNP report →
verify its ECDSA-P384 signature under the VCEK → chain VCEK → ASK → ARK-Milan via
the AMD KDS. The clouds differ only in **how the raw report is obtained**.

---

## A. GCP — direct SEV-SNP guest report

1. Launch an AMD-Milan confidential VM:

   ```bash
   gcloud compute instances create vg-sevsnp \
     --project <PROJECT> --zone us-central1-b \
     --machine-type n2d-standard-2 --min-cpu-platform "AMD Milan" \
     --confidential-compute-type SEV_SNP \
     --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
     --maintenance-policy TERMINATE
   ```

2. Inside the guest, request a report whose `REPORT_DATA` binds your workload key
   (the platform binds an in-TEE X25519 public key as `SHA-512(pubkey ‖ nonce)`,
   see `kms.ExpectedReportData`). GCP exposes the guest device directly, so the
   kernel `configfs-tsm` interface returns a raw report:

   ```bash
   D=/sys/kernel/config/tsm/report/vg
   sudo mkdir -p $D
   printf '<64-byte REPORT_DATA>' | sudo tee $D/inblob >/dev/null
   sudo cat $D/outblob > report.bin       # 1184-byte SNP report
   ```

   (The `geoar-verifier/gcp-cvm/probe-vaultgenome.sh` probe automates the
   key-bind capture and emits the report over the serial console.)

## B. Azure — SEV-SNP via the vTPM/HCL report

Azure mediates SNP through the paravisor and the **vTPM**, so there is **no
`/dev/sev-guest`** and the `configfs-tsm` provider is not wired. The AMD-signed
report is embedded in the **HCL report** stored in vTPM NV index `0x1400001`.

1. Launch a confidential VM (only the `jammy` CVM image is offered in East US):

   ```bash
   az group create -n vg-cvm-rg -l eastus
   az vm create -g vg-cvm-rg -n vg-sevsnp --size Standard_DC4as_v5 \
     --image "Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest" \
     --security-type ConfidentialVM --enable-vtpm true --enable-secure-boot true \
     --os-disk-security-encryption-type VMGuestStateOnly \
     --admin-username azureuser --generate-ssh-keys --public-ip-sku Standard
   ```

2. Read the HCL report from the vTPM. **Two gotchas** (both cost real debugging):

   - Use the **owner hierarchy** auth (`-C o`), not index auth — the index has
     `ownerread`. Index auth or `-C <index>` returns `TPM_RC_BAD_AUTH`.
   - The index is **2900 bytes** — larger than the TPM's max NV read buffer, so
     read it in **≤1024-byte chunks** or the single read fails.

   ```bash
   sudo apt-get install -y tpm2-tools
   sz=$(tpm2_nvreadpublic 0x1400001 | awk '/size/{print $2}')   # 2900
   : > hcl.bin
   for off in $(seq 0 1024 $((sz-1))); do
     chunk=1024; [ $((sz-off)) -lt 1024 ] && chunk=$((sz-off))
     tpm2_nvread -C o 0x1400001 --size $chunk --offset $off -o part.bin && cat part.bin >> hcl.bin
   done
   ```

3. Extract the SNP report — it starts at offset **32** of the HCL blob (a 32-byte
   `HCLA` header precedes it; runtime data follows):

   ```bash
   dd if=hcl.bin of=report.bin bs=1 skip=32 count=1184 2>/dev/null
   ```

   Azure sets `REPORT_DATA` to bind the HCL **runtime data** (the vTPM AK), not an
   arbitrary key; binding a platform key runs through the vTPM AK and is a
   follow-up. The report is genuine (`version 3`, `signing_key = VCEK`,
   `mask_chip_key = 0`).

---

## C. Verify the report chains to AMD

Drop `report.bin` under
`scripts/hardware-test/<cloud>-sev-snp/live-evidence/report.bin` and run the real
verifier — it fetches the VCEK + cert chain from AMD KDS (cached next to the
report for offline reruns):

```bash
go test ./internal/shared/tee/ -run 'TestRealSEVSNP_VerifiesGenuine' -v
```

A PASS means the report parsed, its signature verified under the genuine VCEK,
and the VCEK chained to AMD ARK-Milan — real hardware attestation, not the
simulator. (Committed captures for GCP and Azure already prove this offline.)

## D. Wire the daemon to the real backend

Run `sagvd` **inside** the confidential VM and select the real provider instead
of the simulator:

- `tee.ParseProvider("gcp-sev-snp")` (or the appropriate cloud) resolves the real
  `Producer`/`Verifier` from the registry; `gcp_sev_snp_verify.go`'s `init()`
  wires the real parse/verify/chain functions.
- Populate the cross-cloud **verifier registry** (`verifier_registry_path` in the
  sagvd config) with the expected destination measurement so
  `KindCrossCloudAttestationVerified` is emitted only for genuine hardware.
- For KEM key delivery (`ADR 0009`), configure the Coordinator with
  `BindingVerifier: kms.SEVSNPRecipientBinder{}` and
  `RequireRecipientBinding: true` so DEKs are only wrapped to a pubkey the
  Evidence attests.

## Cleanup (cost hygiene)

Confidential VMs bill per hour — destroy them after capture:

```bash
gcloud compute instances delete vg-sevsnp --zone us-central1-b --quiet     # GCP
az group delete -n vg-cvm-rg --yes --no-wait                               # Azure
```

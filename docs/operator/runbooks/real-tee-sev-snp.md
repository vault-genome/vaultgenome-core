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

2. Inside the guest, request a report whose `REPORT_DATA` binds your workload
   key. (The cross-cloud protocol binds its per-handshake X25519 key by quoting
   over `kms.RecipientChallenge(pubkey, nonce)`, ADR 0009; the standalone probe
   below binds a key with the raw layout `SHA-512(pubkey_DER ‖ nonce)`.) GCP
   exposes the guest device directly, so the kernel `configfs-tsm` interface
   returns a raw report:

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

## D. Run the key-release destination on real SEV-SNP

`acp-bootstrap` requests its reports through configfs-tsm (Linux 6.7 or later,
e.g. the Ubuntu 24.04 image in section A), so on a SEV-SNP Confidential VM it
attests with the chip instead of the simulator:

```json
"tee": { "provider": "gcp-sev-snp", "workload_descriptor": "acp-bootstrap-destination-v1" }
```

No seed is configured — the chip signs. `acp-bootstrap identity -config …` then
prints the guest's 48-byte launch measurement. On the source, register the
family in `sagvd`'s verifier registry with the AMD chain the VCEK must chain to
(AMD KDS serves it at `/vcek/v1/Milan/cert_chain`; the committed capture in
`scripts/hardware-test/gcp-sev-snp/keybind-evidence/` holds a copy):

```json
{ "verifiers": [ {
  "provider": "gcp-sev-snp",
  "expected_measurement_hex": "<measurement_hex from acp-bootstrap identity>",
  "amd_cert_chain_path": "/etc/acp/crosscloud/amd-milan-cert_chain.pem",
  "min_reported_tcb": 0
} ] }
```

and put the same measurement on the allow-list under `"gcp-sev-snp"`. The
verifier fetches each chip's VCEK from AMD KDS (cached per chip and TCB), checks
the ECDSA-P384 signature and the VCEK → ASK → ARK chain, and refuses a report
that is not VCEK-signed, comes from a DEBUG-enabled guest, was requested at a
VMPL other than 0, carries a TCB below `min_reported_tcb`, or does not bind the
ADR 0009 key-binding challenge.

What is still simulated: `sagvd`'s own TEE (the Return Path vault side) and the
SEV-SNP sealer (`SEV_SNP_GUEST_MSG_DERIVED_KEY`). Families other than SEV-SNP are
refused by the registry until their verifiers run end to end.

## Cleanup (cost hygiene)

Confidential VMs bill per hour — destroy them after capture:

```bash
gcloud compute instances delete vg-sevsnp --zone us-central1-b --quiet     # GCP
az group delete -n vg-cvm-rg --yes --no-wait                               # Azure
```

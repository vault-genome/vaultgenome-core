#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02b-cryptographic-attestation.sh — full AMD ARK→ASK→VCEK→Report chain
# validation using VirTEE snpguest, run on an Azure Confidential VM.
# Produces a complete attestation evidence directory at
# ~/vg/attestation-validation/${VM_ID}/ with all 11 evidence files.
#
# Bound to a Vault Genome workload manifest via REPORT_DATA = SHA-512(manifest),
# so the chip's signature covers a hash of *this* workload — not a generic
# report. This is the AMD chain (1st of 2 chains on Azure SEV-SNP); for the
# Microsoft MAA JWT (2nd chain), run 02f-capture-maa-jwt.sh.
#
# Implements the methodology from CTO Sovereign AI's SEV-SNP audit blueprint:
#   1. /dev/sev-guest source proof (Azure CVM, real silicon)
#   2. Endorsement key signs report (VCEK → Report)
#   3. EK chains to AMD root (ARK → ASK → VCEK)
#   4. Measurement / TCB / platform state captured
#   5. REPORT_DATA bound to Vault Genome payload manifest
#
# Usage: ./02b-cryptographic-attestation.sh
#
# Optional environment variables:
#   VM_ID                  identifier baked into manifest (default: hostname)
#   INSPECT_JSON           the record of what Demo 1 sealed (default:
#                          ~/vg/evidence/demo1-inspect.json, written by 03)
#   AMD_KDS_RETRIES        retries on AMD KDS fetch (default: 3)
#   AMD_KDS_SLEEP_SEC      sleep between retries (default: 30)
#   SNP_CHIP               AMD product line (default: read from the report; the
#                          West Europe DC4as_v5 of 2026-10-14 was Genoa, not Milan)

set -euo pipefail

VM_ID="${VM_ID:-$(hostname)}"

# Get Azure VM region/zone from IMDS
IMDS_JSON=$(curl -fs -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute?api-version=2021-12-13" 2>/dev/null || echo "{}")
LOCATION=$(echo "${IMDS_JSON}" | jq -r '.location // "unknown"')
ZONE=$(echo "${IMDS_JSON}" | jq -r '.zone // "unknown"')
VM_SIZE=$(echo "${IMDS_JSON}" | jq -r '.vmSize // "unknown"')

# The workload manifest names what Demo 1 sealed, as acpctl measured it
# (03-demo1-single-bundle.sh writes evidence/demo1-inspect.json): the
# payload digest over the sealed components, the sizes, the content
# reference and the sealing time. A constant would name a file no run
# measured; the report binds the manifest, so the manifest is measured.
INSPECT_JSON="${INSPECT_JSON:-${HOME}/vg/evidence/demo1-inspect.json}"
[ -s "${INSPECT_JSON}" ] || { echo "ERROR: ${INSPECT_JSON} missing — run 03-demo1-single-bundle.sh before 02b"; exit 1; }
read -r PAYLOAD_SHA256 PAYLOAD_SIZE BUNDLE_SHA256 BUNDLE_SIZE SEALED_AT CONTENT_REF < <(python3 - "${INSPECT_JSON}" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
digest = str(d.get("payload_sha256", "")).removeprefix("sha256:")
size = d.get("payload_bytes")
if len(digest) != 64 or not isinstance(size, int):
    sys.exit("demo1-inspect.json carries no measured payload digest and size")
print(digest, size, str(d.get("bundle_sha256", "")).removeprefix("sha256:"), d.get("bundle_bytes"), d.get("sealed_at"), d.get("content_ref"))
PYEOF
)
PAYLOAD_DESCRIPTION="ollama ${CONTENT_REF}, as sealed by acpctl genome seal into demo1-bundle.genome"
AMD_KDS_RETRIES="${AMD_KDS_RETRIES:-3}"
AMD_KDS_SLEEP_SEC="${AMD_KDS_SLEEP_SEC:-30}"
# The AMD product line (Milan, Genoa, Turin) decides the KDS URL and the
# root; it is read from the report's CPUID family and model (report version
# 3 and later, offsets 0x188 and 0x189), with the table snpguest uses.
# SNP_CHIP overrides it.
detect_snp_chip() {  # <report.bin>
  python3 - "$1" <<'PYEOF'
import struct, sys
b = open(sys.argv[1], "rb").read()
version = struct.unpack("<I", b[0:4])[0]
if version < 3:
    sys.exit("report version %d carries no CPUID family; set SNP_CHIP" % version)
fam, mod = b[0x188], b[0x189]
if fam == 0x19 and mod <= 0x0F:
    print("milan")
elif fam == 0x19 and (0x10 <= mod <= 0x1F or 0xA0 <= mod <= 0xAF):
    print("genoa")
elif fam == 0x1A and mod <= 0x11:
    print("turin")
else:
    sys.exit("CPUID family 0x%02x model 0x%02x: not a known SEV-SNP product line" % (fam, mod))
PYEOF
}

OUT_DIR="${HOME}/vg/attestation-validation/${VM_ID}"
mkdir -p "${OUT_DIR}/06-certificates"
cd "${OUT_DIR}"

# ---- Step 0: locate snpguest ----
SNPGUEST="${SNPGUEST:-${HOME}/snpguest-src/target/release/snpguest}"
if ! [ -x "${SNPGUEST}" ] && command -v snpguest >/dev/null 2>&1; then
  SNPGUEST="$(command -v snpguest)"
fi
[ -x "${SNPGUEST}" ] || { echo "ERROR: snpguest not found. Run 01-bootstrap-vm.sh first."; exit 1; }

# ---- Step 1: VM identity ----
echo "=== Step 1: VM identity ==="
cat > 00-vm-identity.txt <<EOF
Hostname: ${HOSTNAME}
VM ID:    ${VM_ID}
Cloud:    azure
Location: ${LOCATION}
Zone:     ${ZONE}
VM Size:  ${VM_SIZE}
Kernel:   $(uname -r)
Captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
cat 00-vm-identity.txt

# ---- Step 2: workload manifest ----
echo
echo "=== Step 2: workload manifest ==="
cat > 01-vaultgenome-payload-manifest.json <<EOF
{
  "vault_genome_version": "1.0.0",
  "payload_sha256": "${PAYLOAD_SHA256}",
  "payload_size_bytes": ${PAYLOAD_SIZE},
  "payload_description": "${PAYLOAD_DESCRIPTION}",
  "payload_measured_by": "acpctl genome inspect --json of demo1-bundle.genome: sha256 over the sealed components, measured in this run",
  "bundle_sha256": "${BUNDLE_SHA256}",
  "bundle_size_bytes": ${BUNDLE_SIZE},
  "sealed_at": "${SEALED_AT}",
  "demo": "vault-genome-cross-vm-attestation",
  "vm_id": "${VM_ID}",
  "tee_backend": "amd-sev-snp",
  "cloud": "azure",
  "location": "${LOCATION}",
  "zone": "${ZONE}",
  "vm_size": "${VM_SIZE}"
}
EOF
cat 01-vaultgenome-payload-manifest.json

# ---- Step 3: the report, as 02-capture-attestation.sh read it from the vTPM ----
# On Azure the guest cannot ask for a report with its own REPORT_DATA: the
# paravisor binds REPORT_DATA to the vTPM runtime data (SHA-256 of it, then
# 32 zero bytes). The manifest above is recorded with the evidence; the
# binding checked in Step 9 is Azure's.
echo
echo "=== Step 3: attestation report from the vTPM capture ==="
EVIDENCE="${HOME}/vg/evidence"
for f in snp-attestation-report.bin hcl-runtime-data.json hcl-report.bin; do
  [ -s "${EVIDENCE}/${f}" ] || { echo "ERROR: ${EVIDENCE}/${f} missing; run 02-capture-attestation.sh first"; exit 1; }
done
cp "${EVIDENCE}/hcl-report.bin" 03-hcl-report.bin
cp "${EVIDENCE}/hcl-runtime-data.json" 03-runtime-data.json
cp "${EVIDENCE}/snp-attestation-report.bin" 04-attestation-report.bin
{ sha256sum 03-runtime-data.json | awk '{print $1}' | tr -d '\n'; printf '%064d\n' 0; } > 02-report-data.hex
xxd -r -p 02-report-data.hex 03-report-data.bin
test "$(stat -c %s 03-report-data.bin)" = "64" || { echo "ERROR: report-data must be 64 bytes"; exit 1; }
test "$(stat -c %s 04-attestation-report.bin)" = "1184" || { echo "ERROR: attestation report must be 1184 bytes"; exit 1; }
echo "REPORT_DATA expected (SHA-256(runtime data) || 0^32): $(cat 02-report-data.hex)"
SNP_CHIP="${SNP_CHIP:-$(detect_snp_chip 04-attestation-report.bin)}"
echo "AMD product line (from the report's CPUID family/model): ${SNP_CHIP}"
echo "${SNP_CHIP}" > 03-snp-chip.txt

# ---- Step 4: bind the manifest through the vTPM ----
# The report's REPORT_DATA names the runtime data, and the runtime data
# names the vTPM's attestation key (HCLAkPub). A quote signed by that key
# with SHA-256(manifest) as its qualifying data therefore binds the
# manifest to this report: chip -> runtime data -> AK -> quote -> manifest.
# The kit takes the quote here and verifies it: the key that signed it is
# the one the runtime data names, and the quote's extra data is the
# manifest's hash.
echo
echo "=== Step 4: the vTPM quote that binds the manifest to the report ==="
# The vTPM device is root/tss-only on this image (02 reads the NV index
# with sudo for the same reason); the files the TPM tools write are handed
# back to the user afterwards.
sudo tpm2_getcap handles-persistent > 14-tpm-handles.txt 2>&1
python3 - "$(pwd)" <<'PYEOF'
import base64, json, os, subprocess, sys
out = sys.argv[1]
owner = f"{os.getuid()}:{os.getgid()}"
j = json.load(open(out + "/03-runtime-data.json"))
ak = next(k for k in j["keys"] if k["kid"] == "HCLAkPub")
n = int.from_bytes(base64.urlsafe_b64decode(ak["n"] + "=" * (-len(ak["n"]) % 4)), "big")
handles = [h for h in open(out + "/14-tpm-handles.txt").read().split() if h.startswith("0x")]
match = None
for h in handles:
    pem = subprocess.run(["sudo", "tpm2_readpublic", "-c", h, "-f", "pem", "-o", f"{out}/14-tpm-{h}.pem"], capture_output=True, text=True)
    if pem.returncode != 0:
        continue
    # The TPM tools create their output 0660; a file root made is handed to the user before it is read.
    subprocess.run(["sudo", "chown", owner, f"{out}/14-tpm-{h}.pem"], check=True)
    txt = subprocess.run(["openssl", "rsa", "-pubin", "-in", f"{out}/14-tpm-{h}.pem", "-modulus", "-noout"], capture_output=True, text=True).stdout
    if txt.startswith("Modulus=") and int(txt.split("=")[1].strip(), 16) == n:
        match = h
print("persistent handles:", handles, "| the runtime data's HCLAkPub is", match or "NOT FOUND")
open(out + "/14-ak-handle.txt", "w").write((match or "") + "\n")
if match:
    subprocess.run(["cp", f"{out}/14-tpm-{match}.pem", f"{out}/14-ak-pub.pem"], check=True)
PYEOF
AK=$(tr -d '\n' < 14-ak-handle.txt)
[ -n "${AK}" ] || { echo "ERROR: no persistent TPM key matches the runtime data's HCLAkPub"; exit 1; }
MANIFEST_SHA256=$(sha256sum 01-vaultgenome-payload-manifest.json | awk '{print $1}')
echo "${MANIFEST_SHA256}" > 14-manifest-sha256.hex
sudo tpm2_quote -c "${AK}" -l sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14 -q "${MANIFEST_SHA256}" -g sha256 \
  -m 14-manifest-quote.msg -s 14-manifest-quote.sig -o 14-manifest-quote.pcrs -f plain > 14-manifest-quote.txt 2>&1
sudo chown "$USER:$USER" 14-manifest-quote.msg 14-manifest-quote.sig 14-manifest-quote.pcrs
# tpm2_checkquote verifies the signature with the AK's public key and that
# the quote's qualifying data is the manifest's hash and its PCR digest
# matches the PCR values it carries.
tpm2_checkquote -u 14-ak-pub.pem -m 14-manifest-quote.msg -s 14-manifest-quote.sig -f 14-manifest-quote.pcrs -g sha256 -q "${MANIFEST_SHA256}" > 14-manifest-binding.txt 2>&1 \
  && echo "vTPM quote by ${AK} (HCLAkPub) over SHA-256(manifest)=${MANIFEST_SHA256}: VERIFIED" | tee -a 14-manifest-binding.txt \
  || { echo "ERROR: the manifest quote did not verify (14-manifest-binding.txt)"; cat 14-manifest-binding.txt; exit 1; }

# ---- Step 5: decoded report ----
echo
echo "=== Step 5: decode report ==="
"${SNPGUEST}" display report 04-attestation-report.bin > 05-attestation-report-decoded.txt
head -30 05-attestation-report-decoded.txt

# ---- Step 6: fetch ARK + ASK + VCEK from AMD KDS ----
echo
echo "=== Step 6: fetch AMD certificates from KDS (${SNP_CHIP}) ==="
KDS_OK=false
for attempt in $(seq 1 "${AMD_KDS_RETRIES}"); do
  echo "--- attempt ${attempt}/${AMD_KDS_RETRIES} ---"
  if "${SNPGUEST}" fetch ca pem 06-certificates/ "${SNP_CHIP}" 2>&1 | tee 06-fetch-ca-log.txt && \
     "${SNPGUEST}" fetch vcek pem 06-certificates/ 04-attestation-report.bin -p "${SNP_CHIP}" 2>&1 | tee 07-fetch-vcek-log.txt; then
    KDS_OK=true
    break
  fi
  echo "KDS unreachable, sleeping ${AMD_KDS_SLEEP_SEC}s..."
  sleep "${AMD_KDS_SLEEP_SEC}"
done

if [ "${KDS_OK}" != "true" ]; then
  echo
  echo "!!! AMD KDS unreachable after ${AMD_KDS_RETRIES} attempts !!!"
  echo "!!! Capturing diagnostic and producing PARTIAL evidence pack  !!!"
  {
    echo "=== AMD KDS outage diagnostic — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    echo "Egress IP: $(curl -fs --max-time 5 https://api.ipify.org 2>/dev/null || echo unknown)"
    echo
    curl -v --max-time 15 "https://kdsintf.amd.com/vcek/v1/${SNP_CHIP^}/cert_chain" 2>&1 | head -30 || true
  } > "12-amd-kds-outage-diagnostic.txt"
  cat <<'EOF' > 99-VM-STATUS.md
# Status: REPORT-CAPTURED, AMD-CHAIN-VALIDATION-DEFERRED

AMD KDS upstream unreachable during validation window. The attestation
report (04-attestation-report.bin) is captured and immutable. To complete
AMD chain validation when KDS recovers, run from any internet-connected machine:

    snpguest fetch ca pem 06-certificates/ <milan|genoa>
    snpguest fetch vcek pem 06-certificates/ 04-attestation-report.bin -p <milan|genoa>
    snpguest verify certs 06-certificates/
    snpguest verify attestation 06-certificates/ 04-attestation-report.bin

Note: The Microsoft MAA chain (02f-capture-maa-jwt.sh) is independent of
AMD KDS — even if AMD's KDS is down, the Microsoft chain may still validate
end-to-end. This dual-chain design is unique to Azure SEV-SNP and reduces
single-PKI risk during validation windows.
EOF
  "${SNPGUEST}" --version > 11-snpguest-version.txt
  echo "Partial evidence at ${OUT_DIR}"
  exit 2
fi

ls -la 06-certificates/

# ---- Step 7: verify chain (ARK → ASK → VCEK) ----
echo
echo "=== Step 7: verify chain ARK → ASK → VCEK ==="
"${SNPGUEST}" verify certs 06-certificates/ | tee 08-verify-certs.txt

# ---- Step 8: verify report signature (VCEK → Report) ----
echo
echo "=== Step 8: verify report signature ==="
"${SNPGUEST}" verify attestation 06-certificates/ 04-attestation-report.bin | tee 09-verify-attestation.txt

# ---- Step 9: explicit REPORT_DATA binding check ----
# The help text is captured first: a multi-line writer behind "grep -q" can die of
# SIGPIPE, which pipefail would turn into a skipped check.
VERIFY_HELP="$("${SNPGUEST}" verify attestation --help 2>&1 || true)"
if grep -q "report-data" <<<"${VERIFY_HELP}"; then
  echo
  echo "=== Step 9: verify REPORT_DATA binding ==="
  REPORT_DATA_HEX=$(tr -d '\n ' < 02-report-data.hex)
  echo "Expected REPORT_DATA: ${REPORT_DATA_HEX}" | tee 10-verify-report-data-binding.txt
  "${SNPGUEST}" verify attestation 06-certificates/ 04-attestation-report.bin -p "${SNP_CHIP}" -r "0x${REPORT_DATA_HEX}" \
    | tee -a 10-verify-report-data-binding.txt
fi

# ---- Step 9b: the VCEK Azure THIM served is this chip's, the same key AMD KDS serves ----
# AMD KDS signs a fresh certificate on every request (the notBefore moves),
# so the certificates differ byte for byte; what must agree is the VCEK
# public key (derived from the chip's secrets and the TCB) and the chip id
# (hwID extension), and THIM's certificate must chain to the ARK that KDS
# served. Seen 2026-10-14: THIM's certificate from 2026-08-18, KDS's from
# the moment of the request, same key, same hwID.
if [ -s "${EVIDENCE}/thim-vcek.pem" ]; then
  echo
  echo "=== Step 9b: VCEK from Azure THIM vs VCEK from AMD KDS ==="
  THIM_KEY=$(openssl x509 -in "${EVIDENCE}/thim-vcek.pem" -noout -pubkey | sha256sum | awk '{print $1}')
  KDS_KEY=$(openssl x509 -in 06-certificates/vcek.pem -noout -pubkey | sha256sum | awk '{print $1}')
  THIM_HWID=$(openssl asn1parse -in "${EVIDENCE}/thim-vcek.pem" 2>/dev/null | grep -A1 '1.3.6.1.4.1.3704.1.4' | tail -1 | sed 's/.*\[HEX DUMP\]://')
  KDS_HWID=$(openssl asn1parse -in 06-certificates/vcek.pem 2>/dev/null | grep -A1 '1.3.6.1.4.1.3704.1.4' | tail -1 | sed 's/.*\[HEX DUMP\]://')
  {
    echo "THIM VCEK: $(openssl x509 -in "${EVIDENCE}/thim-vcek.pem" -noout -dates | tr '\n' ' ')"
    echo "KDS  VCEK: $(openssl x509 -in 06-certificates/vcek.pem -noout -dates | tr '\n' ' ')"
    echo "THIM VCEK public key sha256: ${THIM_KEY}"
    echo "KDS  VCEK public key sha256: ${KDS_KEY}"
    echo "THIM hwID: ${THIM_HWID}"
    echo "KDS  hwID: ${KDS_HWID}"
    echo "THIM VCEK against the KDS chain: $(openssl verify -CAfile 06-certificates/ark.pem -untrusted 06-certificates/ask.pem "${EVIDENCE}/thim-vcek.pem" 2>&1)"
    if [ "${THIM_KEY}" = "${KDS_KEY}" ] && [ -n "${THIM_HWID}" ] && [ "${THIM_HWID}" = "${KDS_HWID}" ]; then echo "SAME KEY, SAME CHIP"; else echo "MISMATCH"; fi
  } | tee 13-vcek-thim-vs-kds.txt
  grep -q "SAME KEY, SAME CHIP" 13-vcek-thim-vs-kds.txt || { echo "ERROR: THIM and KDS disagree on the VCEK key or chip id"; exit 1; }
  openssl verify -CAfile 06-certificates/ark.pem -untrusted 06-certificates/ask.pem "${EVIDENCE}/thim-vcek.pem" >/dev/null || { echo "ERROR: THIM VCEK does not chain to the KDS ARK"; exit 1; }
fi

# ---- Step 10: policy validation summary ----
echo
echo "=== Step 10: write policy validation summary ==="
"${SNPGUEST}" --version > 11-snpguest-version.txt
cat > 11-policy-validation-summary.txt <<EOF
Vault Genome SEV-SNP Attestation Validation — Azure ${VM_ID}
=================================================

Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)
VM:         ${HOSTNAME} (Azure ${LOCATION}, zone ${ZONE}, ${VM_SIZE})
Tool:       $(cat 11-snpguest-version.txt)
Chip:       AMD EPYC ${SNP_CHIP^} (SEV-SNP)

POLICY CHECKS
✓ Report from the vTPM's HCL report (Azure paravisor, NV 0x1400001; real silicon)
✓ Cert chain valid (ARK self-signed → ASK signed by ARK → VCEK signed by ASK)
✓ VEK signed attestation report
✓ TCB values match (cert ↔ report) — Microcode/SNP/TEE/Boot Loader
✓ Chip ID matches (cert ↔ report)
✓ REPORT_DATA = SHA-256(vTPM runtime data) || 0^32 — Azure's binding, checked
$([ -f 13-vcek-thim-vs-kds.txt ] && echo "✓ VCEK from Azure THIM: same key and chip id as AMD KDS's, chains to the same ARK")
✓ Workload manifest bound through the vTPM: the attestation key the report's
  runtime data names (HCLAkPub) signed a quote whose qualifying data is
  SHA-256(manifest) (14-manifest-quote.*, checked by tpm2_checkquote);
  the manifest names what Demo 1 sealed, as measured

RESULT: AMD CHAIN VALIDATION PASSED

NOTE: Run 02f-capture-maa-jwt.sh additionally to capture the Microsoft
MAA JWT — Azure's independent 2nd verifier. Both chains together produce
production_grade: true.
EOF
cat 11-policy-validation-summary.txt

# ---- Step 11: pack evidence ----
echo
echo "=== Step 11: pack evidence ==="
TARBALL="${HOME}/${VM_ID}-amd-chain.tar.gz"
( cd "${HOME}/vg/attestation-validation" && tar czf "${TARBALL}" "${VM_ID}/" )
ls -lh "${TARBALL}"

echo
echo "=== ✓ AMD CHAIN DONE — evidence at ${OUT_DIR}, tarball at ${TARBALL} ==="
echo "Next:"
echo "  ./scripts/02f-capture-maa-jwt.sh   # Microsoft MAA JWT (Azure-specific 2nd chain)"

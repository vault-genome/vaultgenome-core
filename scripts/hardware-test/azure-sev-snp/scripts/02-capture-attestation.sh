#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02-capture-attestation.sh — capture the AMD SEV-SNP attestation report
# on an Azure Confidential VM.
#
# Azure mediates SEV-SNP through its paravisor: the guest has no
# /dev/sev-guest, and the AMD-signed report sits in the vTPM, in the HCL
# report at NV index 0x1400001 (owner hierarchy). Layout, as read on
# 2026-10-14 from a Standard_DC4as_v5 (HCL header version 2):
#
#   offset    0   32 bytes  HCL header: "HCLA", version, report size,
#                           request type, status, reserved
#   offset   32 1184 bytes  the SEV-SNP attestation report
#   offset 1216   20 bytes  runtime-data section header: section size,
#                           version, report type, hash type, data size
#   offset 1236  data size  runtime data: JSON with the vTPM's AK and EK
#                           public keys and the VM configuration
#   then zero padding to the index size (2900 bytes)
#
# The report's REPORT_DATA is SHA-256(runtime data) followed by 32 zero
# bytes: Azure's binding of the report to this vTPM. It is checked here
# before anything else trusts the report.
#
# Outputs (in ~/vg/evidence):
#   hcl-report.bin               the NV index, byte for byte
#   snp-attestation-report.bin   the 1184-byte report
#   hcl-runtime-data.json        the runtime data, byte for byte
#   hcl-layout.txt               parsed headers and the REPORT_DATA check
#   thim-certification.json      VCEK and chain from Azure THIM, with
#   thim-vcek.pem, thim-cert-chain.pem (02b compares them with AMD KDS)
#   kernel-sev.txt
#
# For the ARK -> ASK -> VCEK chain validation run
# 02b-cryptographic-attestation.sh; for the Microsoft MAA JWT run
# 02f-capture-maa-jwt.sh.

set -euo pipefail

cd ~/vg
mkdir -p evidence

HCL_NV_INDEX="0x1400001"

echo "=== read the HCL report from the vTPM (NV index ${HCL_NV_INDEX}) ==="
sudo tpm2_nvread -C o "${HCL_NV_INDEX}" -o evidence/hcl-report.bin
sudo chown "$USER:$USER" evidence/hcl-report.bin
ls -l evidence/hcl-report.bin

echo
echo "=== parse the HCL report; check REPORT_DATA = SHA-256(runtime data) || 0^32 ==="
python3 - <<'PYEOF' | tee evidence/hcl-layout.txt
import hashlib, json, struct, sys
b = open("evidence/hcl-report.bin", "rb").read()
if b[:4] != b"HCLA":
    print("ERROR: HCL signature is %r, not HCLA" % b[:4]); sys.exit(1)
_, ver, report_size, req_type, status = struct.unpack("<5I", b[:20])
report = b[32:32 + 1184]
sec_size, sec_ver, sec_type, hash_type, data_size = struct.unpack("<5I", b[1216:1236])
data = b[1236:1236 + data_size]
print("hcl header:   version=%d report_size=%d request_type=%d status=%d" % (ver, report_size, req_type, status))
print("snp report:   version=%d guest_svn=%d policy=0x%x vmpl=%d" % (
    struct.unpack("<I", report[0:4])[0], struct.unpack("<I", report[4:8])[0],
    struct.unpack("<Q", report[8:16])[0], struct.unpack("<I", report[0x30:0x34])[0]))
print("runtime data: section_size=%d version=%d report_type=%d hash_type=%d data_size=%d"
      % (sec_size, sec_ver, sec_type, hash_type, data_size))
if 32 + 1184 + sec_size != report_size or 20 + data_size != sec_size:
    print("ERROR: the sizes in the headers do not add up"); sys.exit(1)
j = json.loads(data)
print("runtime keys: %s" % [k.get("kid") for k in j.get("keys", [])])
print("vm-config:    %s" % json.dumps(j.get("vm-configuration"), sort_keys=True))
report_data = report[0x50:0x90]
print("report_data:  %s" % report_data.hex())
print("sha256(data): %s" % hashlib.sha256(data).hexdigest())
if report_data != hashlib.sha256(data).digest() + bytes(32):
    print("ERROR: REPORT_DATA is not SHA-256(runtime data) || 0^32"); sys.exit(1)
print("REPORT_DATA = SHA-256(runtime data) || 0^32: OK")
open("evidence/snp-attestation-report.bin", "wb").write(report)
open("evidence/hcl-runtime-data.json", "wb").write(data)
PYEOF

echo
echo "=== file metadata ==="
echo "size in bytes (should be 1184): $(stat -c %s evidence/snp-attestation-report.bin)"
echo "sha256: $(sha256sum evidence/snp-attestation-report.bin | awk '{print $1}')"
xxd -l 96 evidence/snp-attestation-report.bin | tee evidence/snp-attestation-report.hex

echo
echo "=== VCEK and chain from Azure THIM (the certificates for this chip and TCB) ==="
# Azure's Trusted Hardware Identity Management serves the VCEK for this
# VM's chip and TCB from the instance metadata service; 02b compares it
# with what AMD KDS returns for the report.
if curl -fs -H "Metadata: true" "http://169.254.169.254/metadata/THIM/amd/certification" -o evidence/thim-certification.json; then
  jq -r '.vcekCert' evidence/thim-certification.json > evidence/thim-vcek.pem
  jq -r '.certificateChain' evidence/thim-certification.json > evidence/thim-cert-chain.pem
  echo "tcbm: $(jq -r '.tcbm' evidence/thim-certification.json)"
  openssl x509 -in evidence/thim-vcek.pem -noout -subject -issuer
else
  echo "(THIM unavailable; 02b takes the certificates from AMD KDS alone)"
  rm -f evidence/thim-certification.json
fi

echo
echo "=== capture kernel SEV log too ==="
sudo journalctl -k --no-pager 2>/dev/null | grep -iE "sev|memory encryption|tpm" | head -10 \
  > evidence/kernel-sev.txt || true
cat evidence/kernel-sev.txt

echo
echo "=== done. raw attestation captured ==="
echo "Next:"
echo "  ./scripts/02b-cryptographic-attestation.sh  # AMD chain validation"
echo "  ./scripts/02f-capture-maa-jwt.sh            # Microsoft MAA JWT"
echo "  ./scripts/03-demo1-single-bundle.sh         # Demo 1 workload"

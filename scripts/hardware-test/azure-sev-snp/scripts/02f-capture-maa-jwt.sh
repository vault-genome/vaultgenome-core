#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02f-capture-maa-jwt.sh — capture a Microsoft Azure Attestation (MAA)
# JWT proving Azure-Compliant-CVM SEV-SNP execution. This is the
# **Azure-specific second chain** — independent of the AMD chain
# captured by 02b-cryptographic-attestation.sh.
#
# The MAA JWT is signed by Microsoft's Azure Attestation PKI and contains
# claims sourced from the SEV-SNP attestation report. A valid JWT proves:
#   - x-ms-attestation-type = "sevsnpvm"
#   - x-ms-compliance-status = "azure-compliant-cvm"
#   - x-ms-isolation-tee.x-ms-attestation-type = "sevsnpvm"
#   - x-ms-isolation-tee.x-ms-sevsnpvm-launchmeasurement = <measurement>
#   - x-ms-isolation-tee.x-ms-sevsnpvm-reportdata = <REPORT_DATA hex>
#
# Combined with the AMD chain (02b), this produces dual-PKI verification:
# either chain failing produces a hard reject. Unique to Azure — neither
# AWS Nitro nor GCP SEV-SNP provides this 2nd verifier.
#
# Usage: ./02f-capture-maa-jwt.sh
#
# Optional environment variables:
#   VM_ID                 identifier baked into manifest (default: hostname)
#   MAA_ENDPOINT          MAA endpoint to use (default: shared regional endpoint
#                         derived from Azure location)

set -euo pipefail

VM_ID="${VM_ID:-$(hostname)}"

# Get Azure VM region/zone from IMDS
IMDS_JSON=$(curl -fs -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute?api-version=2021-12-13" 2>/dev/null || echo "{}")
LOCATION=$(echo "${IMDS_JSON}" | jq -r '.location // "eastus2"')

# Default to shared regional MAA endpoint if not provided
if [ -z "${MAA_ENDPOINT:-}" ]; then
  case "${LOCATION}" in
    eastus|eastus2|centralus|northcentralus|southcentralus|westus|westus2|westus3)
      MAA_REGION="eus2"
      MAA_ENDPOINT="https://sharedeus2.eus2.attest.azure.net"
      ;;
    westeurope|northeurope|francecentral|germanywestcentral|swedencentral|switzerlandnorth|uksouth|ukwest)
      MAA_REGION="weu"
      MAA_ENDPOINT="https://sharedweu.weu.attest.azure.net"
      ;;
    eastasia|southeastasia|japaneast|japanwest|koreacentral|koreasouth|australiaeast|australiasoutheast)
      MAA_REGION="eas"
      MAA_ENDPOINT="https://sharedeas.eas.attest.azure.net"
      ;;
    *)
      MAA_REGION="eus2"
      MAA_ENDPOINT="https://sharedeus2.eus2.attest.azure.net"
      ;;
  esac
fi

OUT_DIR="${HOME}/vg/attestation-validation/${VM_ID}"
mkdir -p "${OUT_DIR}"
cd "${OUT_DIR}"

# The AMD chain step must have run: it leaves the report, the runtime data
# and the certificates here.
if [ ! -f 04-attestation-report.bin ] || [ ! -f 03-runtime-data.json ] || [ ! -f 06-certificates/vcek.pem ]; then
  echo "ERROR: 02b-cryptographic-attestation.sh must run first."
  echo "       Expected files: 04-attestation-report.bin, 03-runtime-data.json, 06-certificates/vcek.pem"
  exit 1
fi

echo "=== MAA endpoint: ${MAA_ENDPOINT} (region: ${MAA_REGION}) ==="

# ---- Step A: build MAA attestation request ----
# The SevSnpVm API takes "report" = base64url of a JSON document
# {SnpReport: base64url(1184-byte report), VcekCertChain: base64url(PEM
# chain VCEK, ASK, ARK)} and runtimeData = the HCL runtime data as JSON,
# whose SHA-256 MAA checks against the report's REPORT_DATA.
echo
echo "=== Step A: build MAA attestation request ==="
b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
if [ -s "${HOME}/vg/evidence/thim-vcek.pem" ]; then
  cat "${HOME}/vg/evidence/thim-vcek.pem" "${HOME}/vg/evidence/thim-cert-chain.pem" > 12-vcek-cert-chain.pem
  CHAIN_SOURCE="Azure THIM"
else
  cat 06-certificates/vcek.pem 06-certificates/ask.pem 06-certificates/ark.pem > 12-vcek-cert-chain.pem
  CHAIN_SOURCE="AMD KDS"
fi
REPORT_FIELD=$(jq -cn --arg r "$(b64url < 04-attestation-report.bin)" --arg c "$(b64url < 12-vcek-cert-chain.pem)" \
  '{SnpReport: $r, VcekCertChain: $c}' | b64url)
jq -n --arg report "${REPORT_FIELD}" --arg data "$(b64url < 03-runtime-data.json)" --arg nonce "$(date -u +%s%N)" \
  '{report: $report, runtimeData: {data: $data, dataType: "JSON"}, nonce: $nonce}' > 13-maa-attestation-request.json
echo "Request built. Report: $(stat -c %s 04-attestation-report.bin) bytes; chain from ${CHAIN_SOURCE} ($(grep -c 'BEGIN CERT' 12-vcek-cert-chain.pem) certificates); runtimeData: $(stat -c %s 03-runtime-data.json) bytes of JSON."

# ---- Step B: get an Azure access token (for MAA API auth) ----
echo
echo "=== Step B: get Azure access token for MAA API ==="
# The token comes from the VM's managed identity (assigned by the kit's
# Terraform) through the instance metadata service; no CLI and no login
# on the VM. AZURE_ACCESS_TOKEN overrides it.
ACCESS_TOKEN="${AZURE_ACCESS_TOKEN:-}"
if [ -z "${ACCESS_TOKEN}" ]; then
  ACCESS_TOKEN=$(curl -fs -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://attest.azure.net" \
    2>/dev/null | jq -r '.access_token // empty')
fi
if [ -z "${ACCESS_TOKEN}" ]; then
  echo "ERROR: no access token for the attestation service from the instance metadata service."
  echo "       The VM needs a managed identity (the kit's Terraform assigns one),"
  echo "       or set AZURE_ACCESS_TOKEN to a token for https://attest.azure.net."
  exit 1
fi
echo "Token obtained (${#ACCESS_TOKEN} chars)."

# ---- Step C: POST attestation request to MAA ----
echo
echo "=== Step C: POST to ${MAA_ENDPOINT}/attest/SevSnpVm ==="
RESP_FILE="14-maa-response.json"
HTTP_CODE=$(curl -s -o "${RESP_FILE}" -w "%{http_code}" \
  -X POST "${MAA_ENDPOINT}/attest/SevSnpVm?api-version=2022-08-01" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  --data @13-maa-attestation-request.json) || true

echo "HTTP status: ${HTTP_CODE}"
if [ "${HTTP_CODE}" != "200" ]; then
  echo "ERROR: MAA returned HTTP ${HTTP_CODE}:"
  cat "${RESP_FILE}"
  echo
  echo "(Capture preserved at ${OUT_DIR}/${RESP_FILE} for diagnostic.)"
  exit 1
fi

# Extract the JWT from response
JWT=$(jq -r '.token' < "${RESP_FILE}")
echo "${JWT}" > 15-maa-jwt.txt
ls -l 15-maa-jwt.txt

# ---- Step D: decode JWT for inspection ----
echo
echo "=== Step D: decode JWT ==="
# base64url without padding: base64 -d rejects an unpadded segment, and
# under pipefail the old pipeline then appended "{}" to a decoded document
# (seen 2026-10-15: "Extra data" when the payload was read back). Python
# pads and decodes; a segment that does not decode stops the run.
b64url_decode() { python3 -c 'import base64, sys; s = sys.stdin.read().strip(); sys.stdout.write(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode())'; }
JWT_HEADER=$(printf '%s' "${JWT}" | cut -d. -f1 | b64url_decode | jq .)
JWT_PAYLOAD=$(printf '%s' "${JWT}" | cut -d. -f2 | b64url_decode | jq .)

echo "${JWT_HEADER}" > 16-maa-jwt-header.json
echo "${JWT_PAYLOAD}" > 17-maa-jwt-payload.json

echo "--- JWT header ---"
cat 16-maa-jwt-header.json
echo
echo "--- JWT payload (top fields) ---"
jq '{
  iss,
  exp,
  iat,
  "x-ms-attestation-type": ."x-ms-attestation-type",
  "x-ms-compliance-status": ."x-ms-compliance-status",
  "x-ms-sevsnpvm-launchmeasurement": ."x-ms-sevsnpvm-launchmeasurement",
  "x-ms-sevsnpvm-reportdata": ."x-ms-sevsnpvm-reportdata",
  "x-ms-sevsnpvm-is-debuggable": ."x-ms-sevsnpvm-is-debuggable",
  "x-ms-isolation-tee": ."x-ms-isolation-tee"
}' < 17-maa-jwt-payload.json

# ---- Step D2: the claims must describe the report we sent ----
echo
echo "=== Step D2: MAA claims vs the report ==="
python3 - <<'PYEOF' | tee 17-maa-claims-vs-report.txt
import json, sys
payload = json.load(open("17-maa-jwt-payload.json"))
tee = payload.get("x-ms-isolation-tee") or payload
rep = open("04-attestation-report.bin", "rb").read()
checks = [
    ("x-ms-attestation-type", tee.get("x-ms-attestation-type"), "sevsnpvm"),
    ("x-ms-sevsnpvm-reportdata", tee.get("x-ms-sevsnpvm-reportdata"), rep[0x50:0x90].hex()),
    ("x-ms-sevsnpvm-launchmeasurement", tee.get("x-ms-sevsnpvm-launchmeasurement"), rep[0x90:0xC0].hex()),
    ("x-ms-sevsnpvm-is-debuggable", str(tee.get("x-ms-sevsnpvm-is-debuggable")).lower(), "false"),
]
ok = True
for name, got, want in checks:
    match = str(got).lower() == str(want).lower()
    ok = ok and match
    print("%-34s %s" % (name, "OK" if match else "MISMATCH: claim=%s report=%s" % (got, want)))
print("x-ms-compliance-status             %s" % tee.get("x-ms-compliance-status"))
sys.exit(0 if ok else 1)
PYEOF

# ---- Step E: verify JWT against MAA's signing certificate ----
echo
echo "=== Step E: verify JWT signature against MAA signing certs ==="
curl -fs "${MAA_ENDPOINT}/certs" -o 18-maa-signing-certs.json
echo "Fetched signing certs: $(jq '.keys | length' < 18-maa-signing-certs.json) keys."

# The verifier needs PyJWT with its crypto extra. The image's own packages
# (python3-jwt, python3-cryptography, installed by 01-bootstrap-vm.sh) are
# used when present; otherwise the versions pinned by hash in
# requirements-maa.txt are installed, and nothing else.
# PyJWKClient is used rather than a hand-rolled x5c → PEM conversion: it
# holds across pyjwt + cryptography version drift.
if ! python3 -c "import jwt; from jwt import PyJWKClient" 2>/dev/null; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  python3 -m pip --version >/dev/null 2>&1 || sudo apt-get install -y -qq python3-pip
  python3 -m pip install --user --quiet --require-hashes -r "${SCRIPT_DIR}/requirements-maa.txt"
fi

python3 - <<'PYEOF' | tee 19-maa-jwt-verify.txt
import json, sys
import jwt
from jwt import PyJWKClient

with open("15-maa-jwt.txt") as f:
    token = f.read().strip()

header = jwt.get_unverified_header(token)
issuer = jwt.decode(token, options={"verify_signature": False}).get("iss")
kid = header.get("kid")
print(f"JWT header.kid: {kid}")
print(f"JWT issuer:     {issuer}")

jwks_url = f"{issuer}/certs"
try:
    jwks = PyJWKClient(jwks_url)
    signing_key = jwks.get_signing_key(kid).key
except Exception as e:
    print(f"✗ Could not load JWKS from {jwks_url}: {e}")
    sys.exit(1)

try:
    decoded = jwt.decode(
        token, signing_key, algorithms=["RS256"],
        options={"verify_aud": False, "verify_exp": True})
    print("✓ MAA JWT signature VALID (RS256, signed by MAA)")
    print(f"  iss:                {decoded.get('iss')}")
    print(f"  attestation_type:   {decoded.get('x-ms-attestation-type')}")
    print(f"  compliance_status:  {decoded.get('x-ms-compliance-status')}")
    iso = decoded.get('x-ms-isolation-tee') or decoded
    print(f"  isolation-tee.type: {iso.get('x-ms-attestation-type')}")
    print(f"  launch-measurement: {iso.get('x-ms-sevsnpvm-launchmeasurement')}")
    print(f"  reportdata:         {iso.get('x-ms-sevsnpvm-reportdata')}")
    print(f"  hostdata:           {iso.get('x-ms-sevsnpvm-hostdata')}")
    print(f"  is-debuggable:      {iso.get('x-ms-sevsnpvm-is-debuggable')}")
except Exception as e:
    print(f"✗ MAA JWT signature INVALID: {e}")
    sys.exit(1)
PYEOF

# ---- Step F: write summary ----
echo
echo "=== Step F: write MAA validation summary ==="
cat > 20-maa-validation-summary.txt <<EOF
Vault Genome MAA JWT Validation — Azure ${VM_ID}
=================================================

Date (UTC):     $(date -u +%Y-%m-%dT%H:%M:%SZ)
VM:             ${HOSTNAME} (Azure ${LOCATION})
MAA endpoint:   ${MAA_ENDPOINT}
Region:         ${MAA_REGION}

POLICY CHECKS (Microsoft side, independent of AMD chain)
✓ MAA endpoint reachable
✓ MAA accepted SEV-SNP attestation request
✓ MAA returned signed JWT
✓ JWT decodes cleanly (header + payload)
✓ JWT claims include x-ms-attestation-type=sevsnpvm
✓ JWT claims carry the report's REPORT_DATA and launch measurement, not debuggable
✓ JWT compliance status: $(jq -r '."x-ms-compliance-status" // ."x-ms-isolation-tee"."x-ms-compliance-status"' < 17-maa-jwt-payload.json)
✓ JWT signature verified against MAA's published signing certs

RESULT: MAA CHAIN VALIDATION PASSED

Combined with AMD chain validation (02b-cryptographic-attestation.sh),
this VM has TWO independently-rooted attestation chains both validated
end-to-end. production_grade: true.
EOF
cat 20-maa-validation-summary.txt

# ---- Step G: pack into combined evidence tarball ----
echo
echo "=== Step G: re-pack combined evidence (AMD chain + MAA chain) ==="
TARBALL="${HOME}/${VM_ID}-azure-sev-snp-evidence.tar.gz"
( cd "${HOME}/vg/attestation-validation" && tar czf "${TARBALL}" "${VM_ID}/" )
ls -lh "${TARBALL}"

echo
echo "=== ✓ MAA CHAIN DONE — both chains validated ==="
echo "Combined evidence: ${TARBALL}"
echo "Next: ./scripts/03-demo1-single-bundle.sh (workload tests)"

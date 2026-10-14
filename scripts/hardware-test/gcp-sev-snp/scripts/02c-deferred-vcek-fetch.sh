#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02c-deferred-vcek-fetch.sh — complete a deferred SEV-SNP cryptographic
# chain validation when AMD KDS becomes reachable again. Runs from ANY
# internet-connected machine (Mac, Linux laptop, CI runner) — no SEV-SNP
# capable VM required.
#
# Why this works: the attestation report (04-attestation-report.bin) is
# an immutable signed artifact. Chain validation is purely a matter of
# downloading AMD's public certificates and running snpguest verify.
# It can be done at any time, from anywhere with internet access.
#
# Usage:
#   ./02c-deferred-vcek-fetch.sh <path-to-evidence-dir>
#
# Example (Mac):
#   ./02c-deferred-vcek-fetch.sh ~/Desktop/GCP-SEV-SNP-Real-Hardware-Test/07-Cryptographic-Chain-Validation/04-VM4-us-central1-c-PARTIAL/

set -euo pipefail

EVIDENCE_DIR="${1:-}"
[ -n "${EVIDENCE_DIR}" ] || { echo "Usage: $0 <path-to-evidence-dir>"; exit 1; }
[ -d "${EVIDENCE_DIR}" ] || { echo "Not a directory: ${EVIDENCE_DIR}"; exit 1; }
[ -f "${EVIDENCE_DIR}/04-attestation-report.bin" ] || { echo "Missing 04-attestation-report.bin in ${EVIDENCE_DIR}"; exit 1; }

cd "${EVIDENCE_DIR}"
mkdir -p 06-certificates

# ---- Locate or install snpguest ----
SNPGUEST=""
for cand in "$(command -v snpguest 2>/dev/null || true)" \
            "${HOME}/snpguest-src/target/release/snpguest" \
            "${HOME}/.cargo/bin/snpguest" \
            "/usr/local/bin/snpguest"; do
  [ -n "${cand}" ] && [ -x "${cand}" ] && SNPGUEST="${cand}" && break
done

if [ -z "${SNPGUEST}" ]; then
  echo "snpguest not found. Installing from VirTEE upstream (~3 minute compile)..."
  if ! command -v cargo >/dev/null 2>&1; then
    if [[ "$(uname)" == "Darwin" ]]; then
      echo "Install rust first: brew install rustup-init && rustup-init -y"
      exit 1
    else
      # rustup-init 1.29.1 from Rust's archive, checked against its published
      # sha256; the toolchain is the stable release of 2026-09-28. Recorded
      # 2026-10-14 from https://static.rust-lang.org/rustup/release-stable.toml
      # and .../rustup/archive/1.29.1/x86_64-unknown-linux-gnu/rustup-init.sha256
      RUSTUP_INIT_VERSION="1.29.1"
      RUSTUP_INIT_SHA256="dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71"
      RUST_TOOLCHAIN="1.99.0"
      curl -fsSL --proto '=https' --tlsv1.2 "https://static.rust-lang.org/rustup/archive/${RUSTUP_INIT_VERSION}/x86_64-unknown-linux-gnu/rustup-init" -o /tmp/rustup-init
      echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c -
      chmod +x /tmp/rustup-init
      /tmp/rustup-init -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}"
      rm -f /tmp/rustup-init
      # shellcheck disable=SC1091
      . "${HOME}/.cargo/env"
    fi
  fi
  # snpguest v0.10.0 (2025-11-13), the release's commit checked after the
  # clone; cargo builds from the repository's own Cargo.lock.
  SNPGUEST_TAG="v0.10.0"
  SNPGUEST_COMMIT="7705fafb3f6b86cf38ef413aad0e23e52a8db629"
  if [ ! -d "${HOME}/snpguest-src" ]; then
    git -c advice.detachedHead=false clone --depth 1 --branch "${SNPGUEST_TAG}" https://github.com/virtee/snpguest.git "${HOME}/snpguest-src"
  fi
  test "$(git -C "${HOME}/snpguest-src" rev-parse HEAD)" = "${SNPGUEST_COMMIT}" || { echo "ERROR: snpguest ${SNPGUEST_TAG} is not commit ${SNPGUEST_COMMIT}" >&2; exit 1; }
  (cd "${HOME}/snpguest-src" && cargo build --release --locked)
  SNPGUEST="${HOME}/snpguest-src/target/release/snpguest"
fi

echo "Using snpguest: ${SNPGUEST}"
"${SNPGUEST}" --version

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
SNP_CHIP="${SNP_CHIP:-$(detect_snp_chip 04-attestation-report.bin)}"
echo "AMD product line (from the report's CPUID family/model): ${SNP_CHIP}"
echo "${SNP_CHIP}" > 03-snp-chip.txt

# ---- Confirm AMD KDS reachable ----
echo
echo "=== Checking AMD KDS reachability ==="
HTTP_CODE=$(curl -sS --max-time 30 -o /tmp/amd-kds-probe.bin -w "%{http_code}" \
  "https://kdsintf.amd.com/vcek/v1/${SNP_CHIP^}/cert_chain" || echo "000")
echo "HTTP code: ${HTTP_CODE}"
if [ "${HTTP_CODE}" != "200" ]; then
  echo "!!! AMD KDS still unreachable (HTTP ${HTTP_CODE}). !!!"
  echo "Try again later. The captured 04-attestation-report.bin is unchanged"
  echo "and chain validation can be completed any time KDS becomes reachable."
  exit 2
fi
rm -f /tmp/amd-kds-probe.bin

# ---- Fetch ARK + ASK ----
echo
echo "=== Fetch ARK + ASK from KDS ==="
"${SNPGUEST}" fetch ca pem 06-certificates/ "${SNP_CHIP}" 2>&1 | tee 06-fetch-ca-log.txt

# ---- Fetch chip-specific VCEK ----
echo
echo "=== Fetch VCEK for this chip from KDS ==="
"${SNPGUEST}" fetch vcek pem 06-certificates/ 04-attestation-report.bin -p "${SNP_CHIP}" 2>&1 | tee 07-fetch-vcek-log.txt
ls -la 06-certificates/

# ---- Verify cert chain ----
echo
echo "=== Verify ARK → ASK → VCEK ==="
"${SNPGUEST}" verify certs 06-certificates/ | tee 08-verify-certs.txt

# ---- Verify attestation signature ----
echo
echo "=== Verify VCEK signed the attestation report ==="
"${SNPGUEST}" verify attestation 06-certificates/ 04-attestation-report.bin -p "${SNP_CHIP}" | tee 09-verify-attestation.txt

# ---- Verify REPORT_DATA binding (if 02-report-data.hex present) ----
VERIFY_HELP="$("${SNPGUEST}" verify attestation --help 2>&1 || true)"
if [ -f 02-report-data.hex ] && grep -q "report-data" <<<"${VERIFY_HELP}"; then
  echo
  echo "=== Verify REPORT_DATA binding to manifest ==="
  REPORT_DATA_HEX=$(tr -d '\n ' < 02-report-data.hex)
  echo "Expected REPORT_DATA: ${REPORT_DATA_HEX}" | tee 10-verify-report-data-binding.txt
  "${SNPGUEST}" verify attestation 06-certificates/ 04-attestation-report.bin -p "${SNP_CHIP}" -r "0x${REPORT_DATA_HEX}" \
    | tee -a 10-verify-report-data-binding.txt
fi

# ---- Update status note ----
echo
echo "=== Update status ==="
cat > 99-CHAIN-VALIDATION-COMPLETED.md <<EOF
# Status: CHAIN VALIDATION COMPLETED

Deferred validation completed: $(date -u +%Y-%m-%dT%H:%M:%SZ)
snpguest version: $("${SNPGUEST}" --version)

The chain ARK → ASK → VCEK → Report is now fully verified against AMD's
public certificate authority. The attestation report (immutable) was
captured at the original validation window; cryptographic chain
verification is anchored to the same public-key infrastructure regardless
of when AMD KDS becomes reachable.

Verification artifacts:
- 08-verify-certs.txt              ARK → ASK → VCEK signature chain ✓
- 09-verify-attestation.txt        VCEK → Report signature ✓
$([ -f 10-verify-report-data-binding.txt ] && echo "- 10-verify-report-data-binding.txt  REPORT_DATA = SHA-512(manifest) ✓")
EOF
cat 99-CHAIN-VALIDATION-COMPLETED.md

# ---- Remove the old PARTIAL marker if present ----
if [ -f 99-VM4-STATUS.md ] || [ -f 99-VM-STATUS.md ]; then
  echo
  echo "=== Archiving old PARTIAL status note ==="
  mv -f 99-VM4-STATUS.md 99-VM4-STATUS.md.completed 2>/dev/null || true
  mv -f 99-VM-STATUS.md 99-VM-STATUS.md.completed 2>/dev/null || true
fi

echo
echo "=== ✓ DONE — chain validation completed ==="
echo "Add the new artifacts (08, 09, 10, 99) to your evidence package."

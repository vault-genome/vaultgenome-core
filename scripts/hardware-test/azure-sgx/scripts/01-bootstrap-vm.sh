#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 01-bootstrap-vm.sh — install Intel SGX DCAP, Open Enclave SDK, Go,
# Ollama, and the Vault Genome acpctl binary on a fresh Azure DCsv3
# SGX VM. Idempotent — safe to re-run.

set -euo pipefail

# Go 1.27.2 is the toolchain the module names; the tarball is checked
# against its go.dev sha256 before it is unpacked.
GO_VERSION="1.27.2"
GO_SHA256="ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5"  # go.dev/dl, go1.27.2.linux-amd64.tar.gz

# Repository signing keys, checked by fingerprint after download (recorded
# 2026-10-14 with `gpg --show-keys --with-fingerprint`).
INTEL_SGX_KEY_FPR="150434D1488BF80308B69398E5C7F0FA1C6C6C3C"   # CN=Intel(R) Software Development Products
MICROSOFT_KEY_FPR="BC528686B50D79E339D3721CEB3E94ADBE1229CF"   # Microsoft (Release signing) <gpgsecurity@microsoft.com>

# Open Enclave 0.19.19 (2026-10-02) for Ubuntu 22.04, from the project's
# GitHub release, checked against the package's sha256 recorded 2026-10-14.
OE_VERSION="0.19.19"
OE_DEB_SHA256="b9ed505b717e3e108c516fd837bad955d541886354832af7ea9377126d5fcc08"

# import_apt_key <url> <fingerprint> <keyring>: a key whose fingerprint is
# not the recorded one is not installed.
import_apt_key() {
  local url="$1" fpr="$2" keyring="$3" tmp
  tmp="$(mktemp)"
  curl -fsSL "$url" -o "$tmp"
  if ! gpg --batch --quiet --show-keys --with-colons "$tmp" | grep -q "^fpr:::::::::${fpr}:"; then
    echo "ERROR: key at $url does not have fingerprint $fpr; not installing it" >&2
    rm -f "$tmp"
    exit 1
  fi
  sudo gpg --batch --yes --dearmor -o "$keyring" "$tmp"
  rm -f "$tmp"
}

echo "=== verify Intel SGX devices present on this Azure SGX VM ==="
if [ ! -c /dev/sgx_enclave ] || [ ! -c /dev/sgx_provision ]; then
  echo "ERROR: /dev/sgx_enclave and/or /dev/sgx_provision missing."
  echo "       This VM is not running on Intel SGX silicon."
  echo "       Use a Standard_DC*s_v3 VM size (or any DCsv3-family)."
  exit 1
fi
ls -l /dev/sgx_enclave /dev/sgx_provision

echo
echo "=== install build dependencies ==="
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential pkg-config libssl-dev curl git jq tar gnupg lsb-release software-properties-common dkms linux-headers-generic python3-jwt python3-cryptography

echo
echo "=== install Intel SGX DCAP libraries ==="
if ! dpkg -l libsgx-enclave-common 2>/dev/null | grep -q '^ii'; then
  import_apt_key https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
    "${INTEL_SGX_KEY_FPR}" /usr/share/keyrings/intel-sgx-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/intel-sgx-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" \
    | sudo tee /etc/apt/sources.list.d/intel-sgx.list
  sudo apt-get update -qq
  sudo apt-get install -y -qq \
    libsgx-enclave-common libsgx-dcap-default-qpl libsgx-dcap-ql \
    libsgx-dcap-quote-verify libsgx-quote-ex libsgx-urts \
    sgx-aesm-service
fi

# -dev packages for sgx-quote-binding/verify-quote.c (sgx_quote_3.h,
# sgx_dcap_quoteverify.h). Idempotent — apt is a no-op if already
# installed.
sudo apt-get install -y -qq \
  libsgx-dcap-ql-dev libsgx-dcap-quote-verify-dev 2>/dev/null || true
sudo systemctl enable --now aesmd 2>/dev/null || true

echo
echo "=== install Microsoft Azure DCAP client (caches Intel attestation collateral via Azure) ==="
if ! dpkg -l az-dcap-client 2>/dev/null | grep -q '^ii'; then
  import_apt_key https://packages.microsoft.com/keys/microsoft.asc \
    "${MICROSOFT_KEY_FPR}" /usr/share/keyrings/microsoft.gpg
  echo "deb [signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/$(lsb_release -rs)/prod $(lsb_release -cs) main" \
    | sudo tee /etc/apt/sources.list.d/azure-dcap.list
  sudo apt-get update -qq
  sudo apt-get install -y -qq az-dcap-client
fi

echo
echo "=== install Open Enclave SDK (provides oeutil for quote generation + verification) ==="
# History: Intel deprecated download.01.org/openenclave/ (returns 404), and
# Microsoft's prod apt repository no longer carries open-enclave for jammy
# (checked 2026-10-14), so the package comes from the project's GitHub
# release, one version, checked against its sha256 before dpkg sees it.
# Non-fatal: workload tests proceed even if the install fails (smoke-test
# fallback in 02-capture-attestation.sh).
if ! dpkg -l open-enclave 2>/dev/null | grep -q '^ii'; then
  OE_URL="https://github.com/openenclave/openenclave/releases/download/v${OE_VERSION}/Ubuntu_2204_open-enclave_${OE_VERSION}_amd64.deb"
  OE_DEB="$(mktemp)"
  if curl -fsSL --connect-timeout 15 "${OE_URL}" -o "${OE_DEB}" \
     && echo "${OE_DEB_SHA256}  ${OE_DEB}" | sha256sum -c - \
     && sudo apt-get install -y -qq "${OE_DEB}"; then
    echo "✓ Open Enclave ${OE_VERSION} installed from the GitHub release"
  else
    echo "WARNING: Open Enclave ${OE_VERSION} not installed (download, sha256 or apt failed)."
  fi
  rm -f "${OE_DEB}"
fi
# Ensure oeutil is in PATH (Open Enclave installs to /opt/openenclave/bin).
if [ -x /opt/openenclave/bin/oeutil ] && ! command -v oeutil >/dev/null 2>&1; then
  echo 'export PATH=$PATH:/opt/openenclave/bin' >>~/.bashrc
  export PATH=$PATH:/opt/openenclave/bin
fi
if command -v oeutil >/dev/null 2>&1; then
  echo "✓ oeutil at: $(command -v oeutil)"
else
  echo "WARNING: oeutil not available — 02b/02f will use smoke-test fallback."
  echo "         Workload tests (Demo 1 + 2 + tamper + inference) will run normally."
fi

# Two libdcap_quoteprov.so files end up on disk:
#   /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1  ← Intel default QPL
#                                                       (apt: libsgx-dcap-default-qpl)
#                                                       Talks to local PCCS
#                                                       (sgx_default_qcnl.conf →
#                                                        localhost:8081 → not running)
#   /usr/local/lib/libdcap_quoteprov.so               ← Microsoft az-dcap-client
#                                                       Talks to Azure cache
#                                                       (global.acccache.azure.net)
#
# The dynamic loader resolves "libdcap_quoteprov.so" → /usr/lib/x86_64-linux-gnu
# by default, so without intervention we'd use Intel's QPL and fail with
# CURL error 7 (couldn't connect to localhost:8081). Force the dynamic
# loader onto Microsoft's variant by replacing the standard-path symlinks.
echo
echo "=== libdcap_quoteprov.so → Microsoft az-dcap-client (Azure-aware) ==="
if [ -f /usr/local/lib/libdcap_quoteprov.so ]; then
  sudo ln -sf /usr/local/lib/libdcap_quoteprov.so \
              /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so
  sudo ln -sf /usr/local/lib/libdcap_quoteprov.so \
              /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1
  echo "✓ libdcap_quoteprov.so / .so.1 → /usr/local/lib/libdcap_quoteprov.so (az-dcap)"
else
  echo "WARNING: az-dcap-client not at /usr/local/lib/libdcap_quoteprov.so"
  echo "         Quote generation + verification will use Intel QPL"
  echo "         (which fails on Azure without a local PCCS)."
fi

# CRITICAL: aesmd may already be running with the *previous* (Intel)
# QPL cached in memory. Force it to reload by restarting the unit, so
# subsequent oe_get_report / sgx_qe_get_target_info calls go through
# the Microsoft az-dcap-client we just symlinked in.
echo
echo "=== restart aesmd to pick up the swapped libdcap_quoteprov.so ==="
sudo systemctl restart aesmd
sleep 2
sudo systemctl is-active aesmd && echo "✓ aesmd reloaded"

# AESM daemon must be running for oeutil generate-evidence to call into
# the SGX DCAP quoting enclave. Bootstrap above already enabled it via
# systemctl enable --now, but verify here and add azureuser to sgx group
# (so non-root code can use /dev/sgx_provision).
if ! systemctl is-active aesmd >/dev/null 2>&1; then
  echo "(re-starting aesmd...)"
  sudo systemctl restart aesmd 2>/dev/null || true
fi
sudo usermod -a -G sgx_prv "$(whoami)" 2>/dev/null || true

echo
echo "=== install Go ${GO_VERSION} ==="
if ! command -v go >/dev/null 2>&1 || ! go version | grep -q "go${GO_VERSION} "; then
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
  echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c -
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  rm /tmp/go.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin' >>~/.bashrc
  export PATH=$PATH:/usr/local/go/bin
fi
/usr/local/go/bin/go version

echo
echo "=== install Ollama (CPU-only) ==="
if ! command -v ollama >/dev/null 2>&1; then
  # Pinned, not piped: the installer is checked before it runs, like the Go
  # tarball above. Recorded 2026-10-14 with:
  #   curl -fsSL https://ollama.com/install.sh -o install.sh && sha256sum install.sh
  # When ollama.com updates the script, review it and re-record hash and date.
  OLLAMA_INSTALL_SHA256="25f64b810b947145095956533e1bdf56eacea2673c55a7e586be4515fc882c9f"  # ollama.com/install.sh, 2026-10-14
  OLLAMA_INSTALLER="$(mktemp)"
  trap 'rm -f "$OLLAMA_INSTALLER"' EXIT
  curl -fsSL https://ollama.com/install.sh -o "$OLLAMA_INSTALLER"
  if ! echo "${OLLAMA_INSTALL_SHA256}  ${OLLAMA_INSTALLER}" | sha256sum -c -; then
    echo "ERROR: ollama install.sh sha256 mismatch; not running it" >&2
    rm -f "$OLLAMA_INSTALLER"
    exit 1
  fi
  sh "$OLLAMA_INSTALLER"
  rm -f "$OLLAMA_INSTALLER"
fi

echo
echo "=== prepare workdir ==="
mkdir -p ~/vg ~/vg/evidence

echo
echo "=== capture VM identity from Azure IMDS ==="
{
  echo "=== Azure IMDS metadata ==="
  curl -fs -H "Metadata: true" \
    "http://169.254.169.254/metadata/instance?api-version=2021-12-13" 2>/dev/null \
    | jq . || echo "IMDS unavailable"
} | tee ~/vg/evidence/azure-imds.json

echo
echo "=== sanity-check installed tools ==="
FAIL=0
if command -v go >/dev/null 2>&1; then echo "✓ go     $(go version | awk '{print $3}')"; else echo "✗ go MISSING"; FAIL=1; fi
if command -v ollama >/dev/null 2>&1; then echo "✓ ollama $(ollama --version 2>/dev/null | head -1 || echo 'present')"; else echo "✗ ollama MISSING"; FAIL=1; fi
if python3 -c "from jwt import PyJWKClient" 2>/dev/null; then echo "✓ pyjwt  $(python3 -c 'import jwt; print(jwt.__version__)')"; else echo "✗ python3-jwt MISSING (02f will install the pinned wheels)"; fi
if command -v jq >/dev/null 2>&1; then echo "✓ jq     $(jq --version)"; else echo "✗ jq MISSING"; FAIL=1; fi
if [ -c /dev/sgx_enclave ] && [ -c /dev/sgx_provision ]; then echo "✓ /dev/sgx_*"; else echo "✗ /dev/sgx_* MISSING"; FAIL=1; fi
if [ "${FAIL}" = "1" ]; then
  echo
  echo "ERROR: one or more critical tools missing. Workload tests will fail."
  exit 1
fi

echo
echo "=== bootstrap complete ==="
echo "Next: ./scripts/02-capture-attestation.sh"

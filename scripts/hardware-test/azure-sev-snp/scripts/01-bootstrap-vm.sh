#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 01-bootstrap-vm.sh — install Go, Ollama, snpguest, tpm2-tools and the
# Vault Genome acpctl binary on a fresh Azure Confidential VM
# (DCasv5/DCadsv5). Idempotent — safe to re-run.
#
# Prereq: this script runs ON THE VM (after SSH'ing in), not on your
# laptop. Run as a non-root user with sudo access (the Azure default
# 'azureuser' has it).

set -euo pipefail

# Go 1.27.2 is the toolchain the module names; the tarball is checked
# against its go.dev sha256 before it is unpacked.
GO_VERSION="1.27.2"
GO_SHA256="ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5"  # go.dev/dl, go1.27.2.linux-amd64.tar.gz

echo "=== install build dependencies ==="
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential pkg-config libssl-dev curl git jq tar xxd tpm2-tools python3-jwt python3-cryptography

echo
echo "=== verify this is an Azure Confidential VM (SEV-SNP behind the paravisor, report in the vTPM) ==="
# On Azure the guest has no /dev/sev-guest: the paravisor mediates SEV-SNP
# and places the AMD-signed report in the vTPM's HCL report, NV index
# 0x1400001 (02-capture-attestation.sh reads it). The kernel log needs
# root to read and is informational.
sudo journalctl -k --no-pager 2>/dev/null | grep -iE "sev|memory encryption" | head -5 || true
if [ ! -c /dev/tpmrm0 ]; then
  echo "ERROR: no vTPM (/dev/tpmrm0). Use a Standard_DC*as_v5 / DC*ads_v5 size with security type ConfidentialVM."
  exit 1
fi
# Captured first, not piped into grep -q: the writer would die of SIGPIPE on the
# early exit and pipefail would read that as "absent" (seen 2026-10-14 23:03Z).
NV_PUBLIC="$(sudo tpm2_nvreadpublic 2>/dev/null || true)"
if ! grep -q '^0x1400001:' <<<"${NV_PUBLIC}"; then
  echo "ERROR: NV index 0x1400001 (HCL report) absent: not an Azure Confidential VM with the SEV-SNP paravisor."
  exit 1
fi
echo "vTPM present; HCL report at NV index 0x1400001"

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
echo "=== install Ollama (CPU-only — Confidential VMs don't expose GPUs) ==="
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
echo "=== install snpguest (VirTEE) for Cryptographic Attestation Chain Validation ==="
if ! [ -x "${HOME}/snpguest-src/target/release/snpguest" ]; then
  if ! command -v cargo >/dev/null 2>&1; then
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
  # snpguest v0.10.0 (2025-11-13), the release's commit checked after the
  # clone; cargo builds from the repository's own Cargo.lock.
  SNPGUEST_TAG="v0.10.0"
  SNPGUEST_COMMIT="7705fafb3f6b86cf38ef413aad0e23e52a8db629"
  if [ ! -d "${HOME}/snpguest-src" ]; then
    git -c advice.detachedHead=false clone --depth 1 --branch "${SNPGUEST_TAG}" https://github.com/virtee/snpguest.git "${HOME}/snpguest-src"
  fi
  test "$(git -C "${HOME}/snpguest-src" rev-parse HEAD)" = "${SNPGUEST_COMMIT}" || { echo "ERROR: snpguest ${SNPGUEST_TAG} is not commit ${SNPGUEST_COMMIT}" >&2; exit 1; }
  (cd "${HOME}/snpguest-src" && cargo build --release --locked)
fi
"${HOME}/snpguest-src/target/release/snpguest" --version

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
echo "=== bootstrap complete ==="
echo "Next: ./scripts/02-capture-attestation.sh"

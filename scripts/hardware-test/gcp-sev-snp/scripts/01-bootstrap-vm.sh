#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 01-bootstrap-vm.sh — install Go, Ollama, and the Vault Genome acpctl
# binary on a fresh Confidential VM. Idempotent — safe to re-run.
#
# Prereq: this script runs ON THE VM (after SSH'ing in), not on your
# laptop. Run as a non-root user with sudo access (the GCP default).

set -euo pipefail

# Go 1.27.2 is the toolchain the module names; the tarball is checked
# against its go.dev sha256 before it is unpacked.
GO_VERSION="1.27.2"
GO_SHA256="ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5"  # go.dev/dl, go1.27.2.linux-amd64.tar.gz

echo "=== verify SEV-SNP active ==="
if ! journalctl -k --no-pager 2>/dev/null | grep -q "SEV-SNP"; then
  echo "WARNING: SEV-SNP not visible in kernel log — VM may not be a Confidential VM."
fi
journalctl -k --no-pager 2>/dev/null | grep -iE "sev|memory encryption" | head -10

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
echo "=== prepare workdir ==="
mkdir -p ~/vg ~/vg/evidence

echo
echo "=== bootstrap complete ==="
echo "Next: ./scripts/02-capture-attestation.sh"

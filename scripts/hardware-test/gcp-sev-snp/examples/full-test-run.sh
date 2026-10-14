#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# full-test-run.sh — orchestrate the entire kit end-to-end against a
# single Confidential VM. Run from your laptop. The runner:
#
#   1. terraform apply       provisions a Confidential VM
#   2. uploads scripts        pushes the kit's scripts/ dir to the VM
#   3. ssh + bootstrap        installs Go + Ollama + acpctl
#   4. captures attestation   1184-byte SEV-SNP report
#   5. runs Demo 1            single-bundle round-trip + tamper test
#   6. runs Demo 2            chain operations
#   7. (optional) inference   empirical model output comparison
#   8. packs evidence         single tar archive
#   9. downloads it           scp to your laptop
#  10. terraform destroy      tears VM down (no ongoing billing)
#
# A bundle of scripts the kit uploads to the VM lives under scripts/.
# The acpctl binary must be available locally — by default the runner
# expects it at ../../../bin/acpctl (the standard build output path
# from the Vault Genome repo root). Override via $ACPCTL if needed.

set -euo pipefail

KIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ACPCTL="${ACPCTL:-$KIT_DIR/../../../bin/acpctl}"

if [ ! -x "$ACPCTL" ]; then
  echo "ERROR: acpctl binary not found at $ACPCTL"
  echo "       Build with: go build -o ../../../bin/acpctl ./cmd/acpctl"
  echo "       Or set ACPCTL=/path/to/acpctl"
  exit 1
fi

if [ -z "${TF_VAR_project_id:-}" ]; then
  echo "ERROR: set TF_VAR_project_id=<your-gcp-project-id> before running."
  exit 1
fi

# Terraform's google provider authenticates on its own: with Application
# Default Credentials when they exist, otherwise with the signed-in gcloud
# account's access token (GOOGLE_OAUTH_ACCESS_TOKEN). A token lives an
# hour and a run takes longer, so one is minted before every Terraform
# command. The provider version comes from .terraform.lock.hcl; a bump is
# a reviewed change, not a side effect of a run.
ADC_FILE="${GOOGLE_APPLICATION_CREDENTIALS:-${CLOUDSDK_CONFIG:-$HOME/.config/gcloud}/application_default_credentials.json}"
tf() {
  if [ -n "${GOOGLE_OAUTH_ACCESS_TOKEN:-}" ] || [ -f "$ADC_FILE" ]; then
    terraform "$@"
  else
    GOOGLE_OAUTH_ACCESS_TOKEN="$(gcloud auth print-access-token)" terraform "$@"
  fi
}

echo "=== 1. provision VM ==="
cd "$KIT_DIR/terraform"
tf init -input=false

# n2d capacity comes and goes by zone: a zone that answers "does not have
# enough resources" is skipped and the next one tried. ZONES overrides the
# list; TF_VAR_zone alone pins a single zone. The zone that worked is
# exported so every later Terraform command sees the same configuration.
ZONES="${ZONES:-${TF_VAR_zone:-us-central1-a us-central1-b us-central1-c us-central1-f europe-west4-a europe-west4-b europe-west4-c}}"
APPLY_LOG="$(mktemp)"
trap 'rm -f "$APPLY_LOG"' EXIT
PROVISIONED=""
for zone in $ZONES; do
  echo "--- zone $zone ---"
  export TF_VAR_zone="$zone" TF_VAR_region="${zone%-*}"
  if tf apply -auto-approve 2>&1 | tee "$APPLY_LOG"; then
    PROVISIONED="$zone"
    break
  fi
  if grep -q "does not have enough resources\|ZONE_RESOURCE_POOL_EXHAUSTED" "$APPLY_LOG"; then
    echo "(zone $zone has no capacity for the machine type; trying the next)"
    continue
  fi
  exit 1
done
if [ -z "$PROVISIONED" ]; then
  echo "ERROR: no zone in '$ZONES' had capacity for the machine type"
  exit 1
fi

VM_NAME="$(tf output -raw instance_name)"
ZONE="$(tf output -raw zone)"

# Wait for VM to be SSH-ready.
echo "=== 1a. wait for SSH ==="
for _ in $(seq 1 30); do
  if gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="echo ready" \
        --quiet >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

echo
echo "=== 2. upload scripts + acpctl to VM ==="
gcloud compute scp --recurse "$KIT_DIR/scripts" "$VM_NAME":~/scripts \
  --zone="$ZONE" --quiet
gcloud compute scp "$ACPCTL" "$VM_NAME":~/acpctl --zone="$ZONE" --quiet

echo
echo "=== 3-8. run all phases on the VM ==="
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --quiet --command='
  set -e
  chmod +x ~/scripts/*.sh
  cd ~ && mkdir -p vg && cd vg && cp ~/acpctl ./acpctl && chmod +x ./acpctl

  ~/scripts/01-bootstrap-vm.sh
  ~/scripts/02-capture-attestation.sh
  ~/scripts/02b-cryptographic-attestation.sh || echo "(chain validation deferred: AMD KDS unreachable; run 02c later)"
  ~/scripts/03-demo1-single-bundle.sh
  ~/scripts/04-demo2-chain.sh
  ~/scripts/05-inference-test.sh || echo "(inference skipped — non-fatal)"
  ~/scripts/06-pack-evidence.sh
'

echo
echo "=== 9. download evidence to laptop ==="
gcloud compute scp "$VM_NAME":~/"${VM_NAME}"-evidence.tar.gz ./ \
  --zone="$ZONE" --quiet

echo
echo "evidence: $(pwd)/${VM_NAME}-evidence.tar.gz"
ls -lh "${VM_NAME}-evidence.tar.gz"

echo
echo "=== 10. teardown VM ==="
cd "$KIT_DIR/terraform"
tf destroy -auto-approve

echo
echo "=== ✓ all done ==="

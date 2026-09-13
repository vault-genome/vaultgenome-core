#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# full-test-run.sh — orchestrate the entire AWS Nitro Enclaves kit
# end-to-end against a single EC2 instance. Run from your laptop.
#
# Workflow:
#   1. terraform apply       provisions m5.xlarge with Nitro Enclaves enabled
#   2. waits for SSH         polls until instance accepts connections
#   3. uploads scripts       scp scripts/ to instance
#   4. ssh + bootstrap        installs nitro-cli, Docker, Go, allocator
#   5. builds .eif image      from acpctl source (PCR0 captured)
#   6. captures attestation   ~3 KB COSE_Sign1 from /dev/nsm
#   7. verifies cert chain    against AWS Nitro Root CA
#   8. runs Demo 1            single-bundle round-trip + tamper test
#   9. runs Demo 2            chain operations
#  10. (optional) inference   empirical model output comparison
#  11. packs evidence         tar archive
#  12. downloads to laptop    scp
#  13. terraform destroy      tears instance down
#
# Required env:
#   TF_VAR_ssh_key_name=<existing-key-pair-name>
#
# Optional env:
#   TF_VAR_region=us-east-2
#   TF_VAR_availability_zone=us-east-2a
#   TF_VAR_instance_name=vault-genome-nitro-test-1

set -euo pipefail

KIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "${TF_VAR_ssh_key_name:-}" ]; then
  echo "ERROR: set TF_VAR_ssh_key_name=<your-aws-keypair-name> before running."
  echo "       Create one in EC2 console > Key Pairs first, then chmod 600 the .pem"
  echo "       and place at ~/.ssh/<key-name>.pem"
  exit 1
fi

SSH_KEY="$HOME/.ssh/${TF_VAR_ssh_key_name}.pem"
if [ ! -f "$SSH_KEY" ]; then
  echo "ERROR: SSH key not found at $SSH_KEY"
  echo "       Place your downloaded EC2 key pair .pem there first."
  exit 1
fi
chmod 600 "$SSH_KEY"

echo "=== 1. provision EC2 instance with Nitro Enclaves enabled ==="
cd "$KIT_DIR/terraform"
terraform init -upgrade -input=false
terraform apply -auto-approve

INSTANCE_ID="$(terraform output -raw instance_id)"
INSTANCE_NAME="$(terraform output -raw instance_name)"
PUBLIC_IP="$(terraform output -raw public_ip)"
AZ="$(terraform output -raw availability_zone)"

echo "Instance: $INSTANCE_ID ($INSTANCE_NAME) at $PUBLIC_IP in $AZ"

echo
echo "=== 1a. wait for SSH ==="
for _ in $(seq 1 60); do
  if ssh -i "$SSH_KEY" \
         -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
         "ec2-user@${PUBLIC_IP}" \
         "echo ready" >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

echo
echo "=== 2. upload scripts + acpctl source to instance ==="
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -r "$KIT_DIR/scripts" \
    "ec2-user@${PUBLIC_IP}:~/scripts"

# We don't ship a prebuilt acpctl binary — the bootstrap will build one
# from source on the instance. To do that, the instance needs the core/
# repo clonable from somewhere. For the hardware test we assume the
# customer has the source on their laptop and rsyncs it up:
CORE_DIR="$(cd "$KIT_DIR/../../.." && pwd)"
echo "uploading core source from $CORE_DIR (excluding heavy dirs)..."
rsync -az -e "ssh -i $SSH_KEY -o StrictHostKeyChecking=no" \
  --exclude='.git' --exclude='node_modules' --exclude='.next' \
  --exclude='.venv' --exclude='dist' --exclude='build' \
  --exclude='target' \
  "$CORE_DIR/" "ec2-user@${PUBLIC_IP}:~/core/"

echo
echo "=== 3-11. run all phases on the instance ==="
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no \
    "ec2-user@${PUBLIC_IP}" 'bash -se' <<'REMOTE'
set -e
chmod +x ~/scripts/*.sh

# Reflog for group changes if nitro-cli already installed via bootstrap
~/scripts/01-bootstrap-vm.sh
# Need to re-source group memberships; subshell loses them otherwise
exec sg ne -c "exec sg docker -c '
  set -e
  cd ~/core/core
  ~/scripts/02-build-enclave-image.sh
  ~/scripts/02-capture-attestation.sh
  ~/scripts/02b-cryptographic-attestation.sh
  ~/scripts/03-demo1-single-bundle.sh
  ~/scripts/04-demo2-chain.sh
  ~/scripts/05-inference-test.sh || echo "(inference skipped — non-fatal)"
  ~/scripts/06-pack-evidence.sh
'"
REMOTE

echo
echo "=== 12. download evidence to laptop ==="
EVIDENCE_FILE="${INSTANCE_ID}-${AZ}-aws-nitro-evidence.tar.gz"
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
    "ec2-user@${PUBLIC_IP}:~/${EVIDENCE_FILE}" ./

echo
echo "evidence: $(pwd)/${EVIDENCE_FILE}"
ls -lh "${EVIDENCE_FILE}"

echo
echo "=== 13. teardown EC2 instance ==="
cd "$KIT_DIR/terraform"
terraform destroy -auto-approve

echo
echo "=== ✓ all done ==="
echo "To run a 4-VM cohort, run this script 4 times with different"
echo "TF_VAR_availability_zone (us-east-2a/b/c/d). Each run creates,"
echo "tests, and destroys one instance."

# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Shared by the 7B kit's VM startup script: metadata, GCS through the JSON
# API with the VM's own token (no dependency on which cloud SDK an image
# ships), the pinned Python runtime, and the pinned 7B base model.

md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }
token() { md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'; }
enc() { python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

gcs_get() { # gcs_get <object> <file>
  curl -sSf -H "Authorization: Bearer $(token)" -o "$2" \
    "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$(enc "$1")?alt=media"
}
gcs_put() { # gcs_put <file> <object>
  curl -sSf -X POST -H "Authorization: Bearer $(token)" -H "Content-Type: application/octet-stream" \
    --data-binary @"$1" "https://storage.googleapis.com/upload/storage/v1/b/$BUCKET/o?uploadType=media&name=$(enc "$2")" > /dev/null
}

# The base model, pinned by revision; the genome's manifest pins its bytes.
# Qwen2.5-7B-Instruct: 15.2 GB of bfloat16 safetensors in four shards.
BASE_REPO="Qwen/Qwen2.5-7B-Instruct"
BASE_REV="a09a35458c702b33eeacc393d103063234e8bc28"
python_runtime() { # python_runtime <torch index: https://download.pytorch.org/whl/cu126 or …/whl/cpu>
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq > /dev/null && apt-get install -y -qq python3-venv python3-pip > /dev/null
  python3 -m venv /opt/vg
  # The runtime from the hash-pinned locks, each from its own index (no --extra-index-url,
  # so no index can stand in for another): the worker's packages, torch's dependencies and
  # huggingface_hub from PyPI; on a GPU host the CUDA libraries from PyPI; then the torch
  # wheel for this host alone, from the PyTorch index that carries it.
  PIP="/opt/vg/bin/pip install -q --require-hashes --only-binary=:all:"
  $PIP --index-url https://pypi.org/simple -r /opt/worker/requirements-ci.lock
  case "$1" in
    */cu126) $PIP --index-url https://pypi.org/simple -r /opt/worker/requirements-cuda.lock
             $PIP --no-deps --index-url "$1" -r /opt/worker/requirements-torch-cu126.lock ;;
    */cpu)   $PIP --no-deps --index-url "$1" -r /opt/worker/requirements-torch-cpu.lock ;;
    *)       echo "python_runtime: no lock for the torch index $1" >&2; return 1 ;;
  esac
  /opt/vg/bin/pip freeze > "$OUT/pip-freeze.txt"
}

base_model() {
  /opt/vg/bin/python -c "from huggingface_hub import snapshot_download; snapshot_download('$BASE_REPO', revision='$BASE_REV', local_dir='/opt/base', max_workers=8)"
  du -sh /opt/base > "$OUT/base-size.txt"
}

vg() { PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false /opt/vg/bin/python -m vg_genome "$@"; }

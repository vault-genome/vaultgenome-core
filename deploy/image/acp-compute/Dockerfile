# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The release image of acp-compute. Nothing is compiled here: the binary is
# the one the release job built reproducibly, signed and attested
# (bin/acp-compute, the same bytes the release assets carry). The worker
# restores a genome's model through the vg_genome door (ADR 0013), so the
# image carries Python 3.12, the pinned CPU torch and the worker package
# beside the static binary. The public base model is not in the image: it
# is bind-mounted at /models/base and must hash to the genome's manifest.
# Build context: dist/image-context/acp-compute, staged by release.yml —
# the binary from bin/ and the worker package's locks and code from
# workers/genome (the repository's .dockerignore excludes bin/, so the
# root cannot be the context; the rehearsal v0.6.1-rc1 found it).
#
# Base image pinned by digest (resolved 2026-10-13): bump tag and digest
# together. The lab image that compiles from source is
# deploy/compose/acp-compute/Dockerfile.

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

# The worker's pinned runtime (workers/genome/requirements.txt), installed
# from the hash-pinned locks: every wheel is checked against its sha256, and
# each lock comes from its own index — PyPI for requirements-ci.lock, the
# PyTorch CPU wheel index for the torch wheel alone (--no-deps: torch's
# dependencies are in the first lock). No --extra-index-url: no index can
# stand in for another.
COPY genome/requirements-ci.lock genome/requirements-torch-cpu.lock /opt/vg/workers/genome/
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: \
      --index-url https://pypi.org/simple \
      -r /opt/vg/workers/genome/requirements-ci.lock \
 && python -m pip install --no-cache-dir --require-hashes --only-binary=:all: --no-deps \
      --index-url https://download.pytorch.org/whl/cpu \
      -r /opt/vg/workers/genome/requirements-torch-cpu.lock
COPY genome/vg_genome /opt/vg/workers/genome/vg_genome

COPY acp-compute /usr/local/bin/acp-compute

# Same non-root identity distroless uses, so the read-only bind mounts
# provisioned for it stay readable.
RUN groupadd --gid 65532 nonroot && useradd --uid 65532 --gid 65532 --no-create-home nonroot
USER 65532:65532

ENV PYTHONPATH=/opt/vg/workers/genome \
    PYTHONDONTWRITEBYTECODE=1 \
    TOKENIZERS_PARALLELISM=false \
    HF_HOME=/tmp/hf

# Health only. The worker has no inbound Return Path: it dials sagvd.
EXPOSE 9092

ENTRYPOINT ["/usr/local/bin/acp-compute"]
CMD ["-config", "/etc/acp/config/acp-compute.json"]

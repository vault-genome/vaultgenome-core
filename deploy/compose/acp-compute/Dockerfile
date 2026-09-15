# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Multi-stage build for the acp-compute worker daemon. Same patched Go
# builder and reproducible-build flags as deploy/compose/sagvd/Dockerfile.
# The runtime differs: the worker restores a genome's model through the
# vg_genome door (ADR 0013), so its image carries Python 3.12, the pinned
# CPU torch and the worker package beside the static binary. The public
# base model is not in the image: it is bind-mounted at /models/base
# (docker-compose.yml) and must hash to the genome's manifest.

# ---- build stage ------------------------------------------------------------

FROM golang:1.27.0-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG VERSION=0.0.0-local
ARG COMMIT=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -mod=readonly \
        -trimpath \
        -buildvcs=false \
        -ldflags "-s -w -buildid= -X main.version=${VERSION} -X main.commit=${COMMIT}" \
        -o /out/acp-compute \
        ./cmd/acp-compute

# ---- runtime stage ----------------------------------------------------------

FROM python:3.12-slim-bookworm

# The pinned runtime the worker's determinism is measured on
# (workers/genome/requirements.txt); torch from the CPU wheel index.
COPY workers/genome/requirements.txt /opt/vg/workers/genome/requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip \
 && python -m pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.7.1 \
 && python -m pip install --no-cache-dir -r /opt/vg/workers/genome/requirements.txt
COPY workers/genome/vg_genome /opt/vg/workers/genome/vg_genome

COPY --from=builder /out/acp-compute /usr/local/bin/acp-compute

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

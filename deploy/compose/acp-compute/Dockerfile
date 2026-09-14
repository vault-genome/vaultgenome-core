# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Multi-stage build for the acp-compute worker daemon. Mirror of
# deploy/compose/sagvd/Dockerfile: same patched builder, same distroless
# runtime, same reproducible-build flags. Only the binary and ports
# differ.

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

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/acp-compute /usr/local/bin/acp-compute

# Health only. The worker has no inbound Return Path: it dials sagvd.
EXPOSE 9092

ENTRYPOINT ["/usr/local/bin/acp-compute"]
CMD ["-config", "/etc/acp/config/acp-compute.json"]

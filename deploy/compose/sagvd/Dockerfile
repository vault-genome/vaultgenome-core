# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Multi-stage build for the sagvd authority daemon.
#
# Build context: the repository root (docker-compose.yml passes
# `context: ../..`), which is the Go module root.
#
# Builder: golang:1.27.0-alpine — the same patched toolchain CI and
# release.yml pin (see docs/doctrine/ci-security-policy.md §2).
# Runtime: distroless/static-debian12:nonroot — no shell, no package
# manager, no root, no network tools; one static binary reading JSON
# config and key material from read-only bind mounts.

# ---- build stage ------------------------------------------------------------

FROM golang:1.27.0-alpine AS builder

WORKDIR /src

# Download the module graph before copying the full source so a
# code-only change does not re-download dependencies.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# CGO_ENABLED=0: static binary for distroless.
# -trimpath / -buildvcs=false / empty -buildid: reproducible output.
# -s -w: strip symbol and debug tables.
ARG VERSION=0.0.0-local
ARG COMMIT=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -mod=readonly \
        -trimpath \
        -buildvcs=false \
        -ldflags "-s -w -buildid= -X main.version=${VERSION} -X main.commit=${COMMIT}" \
        -o /out/sagvd \
        ./cmd/sagvd

# ---- runtime stage ----------------------------------------------------------

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/sagvd /usr/local/bin/sagvd

# Must match the listen_address fields in config.json:
# 9443 Return Path (mTLS), 9080 REST API (bearer token), 9091 health.
EXPOSE 9443 9080 9091

# No -config → immediate non-zero exit: an image started without a
# config fails fast and loudly.
ENTRYPOINT ["/usr/local/bin/sagvd"]
CMD ["-config", "/etc/acp/config/sagvd.json"]

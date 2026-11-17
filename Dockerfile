# SPDX-License-Identifier: AGPL-3.0-or-later
#
# VaultGenome / AI Continuity Platform — reference image.
# Builds the one-command cross-hardware regeneration demo (default entrypoint)
# plus the admin CLI. Static binaries on a distroless base — no shell, no libc.
#
#   docker build -t vaultgenome .
#   docker build --build-arg VERSION=v0.3.2 --build-arg COMMIT=$(git rev-parse --short HEAD) -t vaultgenome .
#   docker run --rm vaultgenome                 # runs the demo (simulation mode)
#   docker run --rm --entrypoint acpctl vaultgenome version

# Base images pinned by digest (the builder resolved 2026-11-17, the runtime
# 2026-10-13); bump the tag and the digest together.
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY . .
# .dockerignore excludes .git, so Go can embed no VCS revision and the binary
# cannot recover its own identity at runtime. Pass it in instead, the same way
# the Makefile and the release workflow do:
#   docker build --build-arg VERSION=v0.3.2 --build-arg COMMIT=$(git rev-parse --short HEAD) .
ARG VERSION=0.0.0-dev
ARG COMMIT=none
RUN LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
 && CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o /out/acp-demo ./cmd/acp-demo \
 && CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o /out/acpctl   ./cmd/acpctl

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/acp-demo /usr/local/bin/acp-demo
COPY --from=build /out/acpctl   /usr/local/bin/acpctl
ENTRYPOINT ["/usr/local/bin/acp-demo"]

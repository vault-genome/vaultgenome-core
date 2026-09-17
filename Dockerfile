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

FROM golang:1.27.0-alpine AS build
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

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/acp-demo /usr/local/bin/acp-demo
COPY --from=build /out/acpctl   /usr/local/bin/acpctl
ENTRYPOINT ["/usr/local/bin/acp-demo"]

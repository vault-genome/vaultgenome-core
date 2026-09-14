# SPDX-License-Identifier: AGPL-3.0-or-later
#
# VaultGenome / AI Continuity Platform — reference image.
# Builds the one-command cross-hardware regeneration demo (default entrypoint)
# plus the admin CLI. Static binaries on a distroless base — no shell, no libc.
#
#   docker build -t vaultgenome .
#   docker run --rm vaultgenome                 # runs the demo (simulation mode)
#   docker run --rm --entrypoint acpctl vaultgenome version

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/acp-demo ./cmd/acp-demo \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/acpctl   ./cmd/acpctl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/acp-demo /usr/local/bin/acp-demo
COPY --from=build /out/acpctl   /usr/local/bin/acpctl
ENTRYPOINT ["/usr/local/bin/acp-demo"]

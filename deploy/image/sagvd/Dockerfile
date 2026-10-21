# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The release image of sagvd. Nothing is compiled here: the binary is the
# one the release job built reproducibly, signed and attested (bin/sagvd,
# the same bytes the release assets carry — `docker create` + `docker cp`
# gives it back and `cosign verify-blob` checks it against the release's
# bundle). Build context: the repository root after `make build`.
#
# Runtime: distroless/static-debian12:nonroot — no shell, no package
# manager, no root; one static binary reading JSON config and key material
# from read-only bind mounts. Pinned by digest (resolved 2026-10-13): bump
# tag and digest together.
#
# The lab image that compiles from source is deploy/compose/sagvd/Dockerfile.

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY bin/sagvd /usr/local/bin/sagvd

# Must match the listen_address fields in config.json:
# 9443 Return Path (mTLS), 9080 REST API (bearer token), 9091 health.
EXPOSE 9443 9080 9091

# No -config → immediate non-zero exit: an image started without a
# config fails fast and loudly.
ENTRYPOINT ["/usr/local/bin/sagvd"]
CMD ["-config", "/etc/acp/config/sagvd.json"]

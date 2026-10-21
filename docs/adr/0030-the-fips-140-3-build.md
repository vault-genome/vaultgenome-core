# ADR 0030 — The FIPS 140-3 build: the certified Go Cryptographic Module, approved-mode discipline in every build, and the only-mode assessment on the record

- **Status:** Accepted (2026-10-21) — part one (the code: the v2 suites, the module's AES-GCM and HKDF, bundle v4, the only-mode assessment in the gate) and part two (the kits under `VG_FIPS=1`, C42) in the tree; part three (the `-fips` release matrix) to follow
- **Tags:** crypto, fips, build, release, aead, bundle, hkdf, assessment
- **Extends:** ADR 0029 (the profiles and the suites: what each build may *use*); ADR 0023 (sealed key files); `docs/operator/05_release_procedure.md`
- **Closes:** the rest of finding F2 of the banking map (`docs/compliance/banking.md` §9), once parts one to three are in the tree

## Context

A bank's cryptography policy asks for two things the profile of ADR 0029
does not give by itself: that the algorithms come from a module validated
under FIPS 140-3, and that the module is operated in its approved mode.
The first is a build decision; the second is a discipline in how the
product calls the module, in every build.

Go ships such a module. The Go Cryptographic Module v1.0.0 holds CMVP
certificate #5247 (overall level 1, validated 2026-04-27, updated
2026-07-07, sunset 2031-04-26; CAVP A6650 and A8668), with `fips.o`
tested on linux/amd64, linux/arm, darwin/arm64 and freebsd/amd64
(Security Policy §2.2). A build selects it with `GOFIPS140=v1.0.0`; in
go1.27.3 the alias `certified` resolves to `v1.0.0-c2097c7c` and
`inprocess` to `v1.26.0`, the version under validation (it adds ML-DSA).
Such a build runs with the setting `fips140=on`. The setting
`fips140=only` makes every non-approved algorithm return an error or
panic; Go's own document calls it "a best effort mode meant for testing,
assessment, and debugging … not intended to be used in production".

The module's Security Policy draws the lines that touch this product:

- The approved mode "is entered automatically upon invocation of an
  approved service and exited automatically upon invocation of a
  non-approved service" (§2.4). Approved mode is a property of what the
  caller invokes.
- AES-GCM IVs are generated inside the module: "96 bits random nonces
  generated internally by Counter DRBG, complying with IG C.H Scenario 2"
  (`SealWithRandomNonce`), or deterministically for SSH, TLS 1.2, TLS 1.3
  and a counter construction whose first 32 bits encode the module name
  (§2.7). "No more than 2³² encryptions may be performed with
  SealWithRandomNonce with the same key."
- Table 8, non-approved and not allowed: "AES GCM — using arbitrary nonces
  for encryption"; "HKDF — using secrets shorter than 112 bits"; "HMAC —
  using keys shorter than 112 bits"; "Ed25519ctx"; AES-ECB; GHASH. The
  HMAC key inside HKDF is the salt, "which [is] allowed to be shorter"
  (IG C.M, §2.7).
- Approved: AES-GCM/CTR/CBC/CMAC, SHA-2 and SHA-3, HMAC, HKDF (KDA
  SP 800-56C), ECDSA and ECDH over the NIST curves, EdDSA (Ed25519),
  ML-KEM, RSA, the TLS 1.2 and 1.3 KDFs, Counter and HMAC DRBG. X25519 is
  in no approved table.

**The measurement** (2026-10-21, tree `8c14ee3`, go1.27.3;
`0030-the-fips-140-3-build.measurement-20261021.log` beside this file).
All five commands build under `GOFIPS140=v1.0.0` and are stamped
`GOFIPS140=v1.0.0-c2097c7c`. Under `GODEBUG=fips140=only`, 48 of the 105
test packages fail, for four reasons:

1. **AES-GCM with our own nonces** — 428 refusals, "use of GCM with
   arbitrary IVs is not allowed … use NewGCMWithRandomNonce", at the
   construction of the AEAD. `internal/shared/crypto` `Seal`/`Open` draw a
   random 12-byte nonce and pass it in; `internal/vault/kms/kem.go` (the
   legacy ECIES) does the same; the genome bundle derives each segment's
   nonce from a 7-byte random prefix, the segment's index and a last-flag
   byte. Every sealed thing in the product goes through the first; the
   bundle is its own format.
2. **X25519** — 164 refusals: `hpke-x25519-v1`, the first suite of the
   `general` profile (the tests' default), the legacy `x25519-kem-v1`
   wrapper and the v1 escrow documents.
3. **SHA-1** — one test builds an OCSP response with `x/crypto/ocsp`,
   whose default issuer hash is SHA-1. In production the same package
   parses NVIDIA's OCSP answers (`nvidia_ocsp.go`) with the responder's
   hash, and the Azure confidential-GPU path names a `sha1` PCR bank:
   both on the `azure-cgpu` path, neither on SEV-SNP or TDX.
4. **A hand-rolled HKDF** — `crypto.HKDFSHA256` keys HMAC with the salt
   itself; Go's HMAC refuses keys under 112 bits unless it is called from
   the module's own HKDF (one test, a short salt).

What the measurement did not find: the Return Path handshake, the
session sealing, the audit chain (Ed25519, SHA-256, AES-GCM), the TLS of
every listener (TLS 1.3, ECDSA P-256 certificates from `acp-keygen`), the
P-384 and ML-KEM suites, the integer door — none reached a non-approved
algorithm.

## Decision

1. **The FIPS build is a release variant, named by its module version.**
   The release carries `-fips` variants of the five binaries and the two
   images, built with `GOFIPS140=v1.0.0` from the same commit, by the same
   reproducible build (`verify-reproducible` covers both). The version is
   pinned and written in the release notes and the compatibility ledger —
   never the aliases `certified` or `latest`, which move. `sagvd version`,
   `acp-compute version`, `acp-bootstrap version`, `acpctl version` and
   every `identity` print `fips140.Version()` and `fips140.Enabled()`;
   the SBOM and the provenance carry the build setting. The default build
   stays the default: the `general` profile's first suite is X25519.
2. **`only` is the assessment, never the product.** No binary carries
   `fips140=only`. A CI job runs the unit and integration tests under
   `GODEBUG=fips140=only` with the tests' default profile set to `fips`;
   the hardware kits accept `VG_FIPS=1` — the binaries built with
   `GOFIPS140=v1.0.0`, the guests' daemons run under `fips140=only`, the
   profile `fips` or `cnsa` — and their records say so. The claim is
   narrow: under the `fips` and `cnsa` profiles the product invokes only
   approved services, shown by runs in which anything else would have
   failed.
3. **Approved-mode discipline in every build, one format for all.**
   a. AES-GCM is constructed with `cipher.NewGCMWithRandomNonce`
      everywhere. `crypto.Seal` keeps its shape — the module generates the
      nonce, the helper returns it beside the ciphertext — and
      `crypto.Open` joins the stored nonce back in front; every existing
      sealed thing (key files, session material, tokens, escrow documents,
      continuity proofs) stays byte-identical on disk and on the wire.
      `kms/kem.go` likewise (nonce ‖ ciphertext).
   b. The genome bundle moves to `vault-genome-v4`: a 12-byte
      module-generated nonce stored before each segment's ciphertext, and
      the segment's index and last flag move from the nonce into the AAD
      (`SHA-256(label ‖ header ‖ index ‖ last)`). v3 bundles stay readable
      — the same primitive, the v3 nonce joined in front of the ciphertext
      at read time; every writer writes v4; a bundle has at most 2³²
      segments (the module's limit per key).
   c. HKDF is the module's `crypto/hkdf` (RFC 5869: the same output);
      `crypto.HKDFSHA256` keeps its signature and callers.
   d. Under `fips140=only`, a configuration that names
      `crypto.profile: general` is refused at startup with the reason (it
      offers `hpke-x25519-v2`, which this process cannot make), and a
      configuration that names no profile gets `fips` instead of
      `general` — the default the module can keep; the X25519 and X-Wing
      suites report themselves unavailable; a wrapped key under
      `x25519-kem-v1`, a v1 suite or a v1 escrow document is refused with
      the reason, not a panic. `identity` prints the module's state.
   e. The SHA-1 in the test goes (SHA-256 issuer hash). The two
      production uses — NVIDIA's OCSP issuer hash as the responder chose
      it, the vTPM `sha1` bank name — are named as non-approved uses on
      the `azure-cgpu` path, which stays outside the FIPS claim until it
      is measured on that hardware (its own item).
3f. **The AEAD step of the suites is the module's.** The assessment of
   part one found that Go's `crypto/hpke` cannot seal under `fips140=only`
   ("use of GCM with arbitrary IVs"): HPKE derives each nonce as
   base_nonce ⊕ sequence outside the module, which is Table 8's "AES GCM —
   using arbitrary nonces for encryption" whatever the build. The KEM and
   the KDF are approved; the AEAD step was not. Every suite of ADR 0029
   therefore moves to a v2: HPKE opened export-only (RFC 9180 §5.3, AEAD id
   0xFFFF) exports a 32-byte key for the suite, the purpose and the
   context `vault-genome hpke v2 wrap key`, and the module's AES-256-GCM
   seals under it with the nonce it generates — on the wire `enc ‖ nonce
   ‖ ciphertext ‖ tag`. The recipient keys are the same (a key belongs to
   its KEM, not to a version): a key made by 0.7.0 under `hpke-p384-v1`
   writes and opens `hpke-p384-v2` unchanged, and the escrow documents and
   sealed key files of 0.7.0 open as they are, by the suite they record.
   The v1 suites stay known and read-only: what 0.7.0 wrapped opens on a
   build without enforcement, nothing writes them, and under
   `fips140=only` they name their refusal. The profiles list v2 suites
   only — `general` writes `hpke-x25519-v2`, `fips` `hpke-p384-v2`, `cnsa`
   `hpke-mlkem1024-p384-v2` — so a 0.7.0 authority and a 0.8 destination,
   or the reverse, meet on no suite and release nothing: both daemons move
   together, as ADR 0029 ruled. (Decided 2026-10-21 after the
   measurement; probed: export-only HPKE with P-384, ML-KEM-768 and the
   hybrid runs under `fips140=only`.)
4. **Not decided here:** signatures beyond Ed25519 and SHA-256 (F2b);
   the move to v1.26.0 (a ledger entry when it is certified); a FIPS claim
   for the confidential-GPU path.

## Alternatives considered

- **`//go:debug fips140=only` baked into the `-fips` binaries.** Rejected:
  Go says the mode is not for production and "introduces crashes";
  approved mode is which services are invoked, and the profiles of ADR
  0029 already pin that. The assessment runs it; the product does not.
- **Keep the bundle's counter nonces with the module's counter
  construction.** Rejected: that construction fixes the first 32 bits to
  the module's name and is not in Go 1.27's public API; a stored random
  nonce costs 12 bytes per segment of a mebibyte.
- **A separate FIPS flavour of the formats.** Rejected: one format,
  readable across versions, is the doctrine of ADR 0029 ("both daemons
  move together"); a FIPS deployment and a general one must exchange
  bundles and escrow documents.
- **`GOFIPS140=certified` or `latest`.** Rejected: the module version is
  part of what a bank records; it must be named, not resolved at build
  time.
- **Skip the discipline in the default build and fix only `-fips`.**
  Rejected: the explicit-nonce AES-GCM is a non-approved service in the
  module's own terms whatever the build; the same bytes should seal a
  thing in both builds.

## Consequences

- Every build becomes approved-mode clean in its AEAD and KDF use; users
  of the default build see no change but the bundle format.
- Bundles written from the next release are v4; a reader of the previous
  release cannot open them, while v3 bundles open everywhere. A
  deployment upgrades its readers (`acpctl`, `sagvd`, the sentinel,
  `acp-bootstrap`) before its writers; the compatibility ledger says so.
- The release doubles its binaries and images (ten and four); the images
  job, the rehearsal of §4.1 and the two release kits cover the `-fips`
  set like the others.
- The only-mode job adds about a minute to CI and will refuse a change
  that reaches a non-approved algorithm under the `fips` profile.
- On a `-fips` binary under `fips140=only`, the `general` profile and the
  legacy X25519 documents are unavailable; under `on` they work and are
  non-approved — the operator's record names which build and which
  profile ran.

## Implementation notes

- **Part one (code, all builds):** the v2 suites (3f); `crypto.NewGCM` → `NewGCMWithRandomNonce`
  with the split/join helpers; `kms/kem.go`; bundle v4 with v3 reading and
  the AAD change; `crypto/hkdf`; only-mode awareness
  (`fips140.Enforced()`), the refusals of 3d, `identity`/`version`
  fields; the tests' default profile by mode; the SHA-1 test; the CI job
  `fips140-only`. The gate: `go test ./...` green under
  `GOFIPS140=v1.0.0 GODEBUG=fips140=only`.
- **Part two (proof):** `VG_FIPS=1` in `keyrelease-e2e`, `returnpath-e2e`
  and `reference-design-01` — the binaries built with `GOFIPS140=v1.0.0`,
  every Go process on the guests (and design 01's third party on the
  runner) under `GODEBUG=fips140=only`, the record saying so on every
  party (each daemon's `version` line and `identity`, the guest's
  `steps.txt`, the runner's `build.txt`), the verdict requiring it; runs
  on SEV-SNP under `fips` and `cnsa` (2026-10-21); claim C42; the cGPU
  measurement listed as open.
- **Part three (release):** the `-fips` matrix in `release.yml` (binaries,
  images, SBOMs, provenance, the images list), an rc rehearsal (§4.1),
  `05_release_procedure.md`, the ledger in `08_upgrading.md` (bundle v4,
  the module version), `banking.md` §6 and §9 (F2 closed), `controls.md`,
  `CHANGELOG.md`, `README.md`.

## References

- CMVP certificate #5247, Go Cryptographic Module v1.0.0 — the
  certificate page and the Security Policy (`140sp5247`), §2.2, §2.4,
  §2.7, Table 8; the consolidated certificate of April 2026.
- Go: "FIPS 140-3 Compliance" (`go.dev/doc/security/fips140`); the
  `GODEBUG` reference (`fips140`); go1.27.3 `lib/fips140/{certified,
  inprocess,v1.0.0}.txt` and `fips140.sum`; `crypto/fips140`
  (`Enabled`, `Enforced`, `Version`); `crypto/cipher.NewGCMWithRandomNonce`;
  `crypto/hkdf`.
- NIST FIPS 140-3; the Implementation Guidance (C.H on GCM IVs, C.M on
  HMAC keys, D.N on PBKDF); SP 800-38D; SP 800-56C Rev. 2; RFC 5869.
- ADR 0009 (the X25519 KEM), ADR 0023 (sealed key files), ADR 0029 (suites
  and profiles); `docs/compliance/banking.md` §6 and §9 (F2).
- The measurement: `0030-the-fips-140-3-build.measurement-20261021.log`.

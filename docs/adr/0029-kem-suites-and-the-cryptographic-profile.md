# ADR 0029 — KEM suites and the cryptographic profile: HPKE for every key encapsulation, pinned by policy, named in every record

- **Status:** Proposed (2026-10-21) — Accepted when the implementation lands
- **Tags:** crypto, kms, escrow, crosscloud, fips, post-quantum, profile
- **Extends:** ADR 0009 (X25519 KEM for cross-cloud DEK delivery) — its rule stands, its construction is replaced
- **Closes:** finding F2 of the banking map (`docs/compliance/banking.md` §9)

## Context

Three places in the product encapsulate a key to a public key, and all
three use one construction, the ECIES of ADR 0009: an ephemeral X25519
key, HKDF-SHA256, AES-256-GCM (`kms.X25519KeyWrapper`), recorded in the
audit chain as `delivery_mode = "x25519-kem-v1"`.

1. Cross-cloud DEK delivery: `sagvd` encapsulates each DEK to the key the
   destination TEE generated for that handshake and bound into its
   Evidence; `acp-bootstrap` opens it (ADR 0009).
2. Genome key escrow: `acpctl genome seal --escrow-to` encapsulates the
   fresh DEK to the authority's published escrow key
   (`vault-genome/key-escrow/v1`); the escrow private key is sealed to the
   host (`vault-genome/sealed-escrow-key/v1`) and can be re-encapsulated
   to a recovery key (`vault-genome/escrow-recovery/v1`).
3. The RATS roles' key material around those two: `sagvd escrow-provision`
   loads the escrow key; both daemons report what they sealed.

The banking map (F2) found what this construction is not. X25519 is not
an approved key-establishment scheme: SP 800-56A Rev. 3 specifies ECC CDH
over the NIST curves, SP 800-186 lists Curve25519 among the curves it
describes but SP 800-56A does not admit it for key agreement, and the
registry X9 SD-34 (2025) that banks' auditors read has no entry for it.
The Go Cryptographic Module's security policy (CMVP #5247) lists, as
approved, KAS-ECC-SSC over P-224/P-256/P-384/P-521, the HKDF key
derivation of SP 800-56C Rev. 2, and ML-KEM-768 and ML-KEM-1024 key
generation and encapsulation (FIPS 203) — and no X25519. A United States
federal buyer requires a validated module and approved algorithms; the
NSA's CNSA 2.0 (advisory of 2022-09-07) names P-384 and SHA-384 for the
transition and ML-KEM-1024 as the destination, with "prefer by 2025,
exclusively by 2030" for software and firmware and "by 2033" for the
rest; NIST IR 8547 (initial public draft, 2024-11) puts every
quantum-vulnerable algorithm — the NIST curves included — at "Deprecated
after 2030, Disallowed after 2035". A P-384 option alone would therefore
close the finding for a few years and open it again.

What the toolchain offers changed in 2026. Go 1.27's standard library
has `crypto/hpke`, RFC 9180 with DHKEM over P-256, P-384, P-521 and
X25519 (KEM ids 0x0010, 0x0011, 0x0012, 0x0020), the post-quantum and
hybrid KEMs of draft-ietf-hpke-pq-05 — ML-KEM-768 (0x0041), ML-KEM-1024
(0x0042), MLKEM768-P256 (0x0050), MLKEM1024-P384 (0x0051), MLKEM768-X25519
(X-Wing, 0x647a) — the KDFs HKDF-SHA256/384/512 and the AEADs
AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305; `crypto/mlkem`;
`crypto/fips140` with `Enabled`, `Enforced` and `Version`, where
`GOFIPS140=v1.0.0` builds with the module certified under #5247 and
`GODEBUG=fips140=only` makes a non-approved algorithm fail instead of
run. `crypto/x509` carries X25519, ECDSA and ML-DSA keys in PKIX form,
not ML-KEM keys.

What must not change. ADR 0009's rule: a DEK crosses clouds only as a
key encapsulation to a key the destination generated for that handshake
and bound in its Evidence; no private key is configured, stored or
transmitted; there is no symmetric wrap and no fallback. The
compatibility ledger (`docs/operator/08_upgrading.md`): no release has
changed the bundle format, and escrow envelopes written by earlier
releases must still open. The wires: both daemons move together (0.5.0).
Invariant 09: a contract keeps `SchemaVersion` first and its
`Min`/`Max`/`Current` constants.

## Decision

1. **HPKE is the one construction.** Every new encapsulation is RFC 9180
   HPKE in base mode, through `crypto/hpke` of the standard library: a
   KEM, a KDF and an AEAD chosen by suite; `info` is the product's domain
   label, the suite id and the context the ECIES put into its HKDF info;
   the AAD is what it is today (the token's binding, the escrow key id).
   The ECIES of ADR 0009 stays in the tree only as the reader of what
   releases 0.1.0 to 0.6.1 wrote (`x25519-kem-v1`); nothing writes it
   after this ADR lands.

2. **Suites, named.** A suite is a string id over a triple of HPKE
   identifiers. The registry at launch:

   | Suite | KEM | KDF | AEAD | Profiles that allow it |
   | - | - | - | - | - |
   | `hpke-x25519-v1` | DHKEM(X25519, HKDF-SHA256) `0x0020` | HKDF-SHA256 `0x0001` | AES-256-GCM `0x0002` | general |
   | `hpke-p384-v1` | DHKEM(P-384, HKDF-SHA384) `0x0011` | HKDF-SHA384 `0x0002` | AES-256-GCM | fips, general |
   | `hpke-mlkem768-v1` | ML-KEM-768 `0x0041` | HKDF-SHA256 | AES-256-GCM | fips, general |
   | `hpke-mlkem1024-p384-v1` | MLKEM1024-P384 `0x0051` (hybrid, SP 800-227 §4.6; the shared secret Z′ = Z ‖ T of SP 800-56C Rev. 2) | HKDF-SHA384 | AES-256-GCM | cnsa, fips, general |
   | `hpke-xwing-v1` | MLKEM768-X25519 `0x647a` (X-Wing) | HKDF-SHA256 | AES-256-GCM | general |
   | `x25519-kem-v1` | the ECIES of ADR 0009 | — | — | general, read only |

   A suite id never changes meaning; a new triple is a new id.

3. **The profile.** `crypto.profile` in both daemons' configuration and
   in `acpctl` — `general` (the default), `fips`, `cnsa` — names the
   suite a daemon writes and the list it accepts:

   | Profile | Writes | Accepts |
   | - | - | - |
   | `general` | `hpke-x25519-v1` | every suite of the table, `x25519-kem-v1` included |
   | `fips` | `hpke-p384-v1` | `hpke-p384-v1`, `hpke-mlkem768-v1`, `hpke-mlkem1024-p384-v1` |
   | `cnsa` | `hpke-mlkem1024-p384-v1` | `hpke-mlkem1024-p384-v1` |

   `crypto.kem_suites` may narrow a profile's list further, never widen
   it. There is no negotiation below the list: the source's handshake
   request carries the suites it accepts, in its order of preference;
   the destination generates its handshake key under the first it
   supports and names that suite in its answer; the source refuses an
   answer whose suite is not on its list. A destination of an earlier
   release answers without a suite, which means `x25519-kem-v1`, and is
   accepted only where the list has it — so a `fips` authority refuses an
   earlier-release destination at the handshake, on the record, instead
   of sealing to a key it must not use.

4. **Where the suite is written.**
   - The handshake answer carries `recipient_key_suite` beside
     `recipient_public_key` (the HTTP answer and `kms.HandshakeResponse`),
     and the key-binding challenge of ADR 0009 gains a second version
     that commits to the suite as well as the key:
     `C₂ = SHA-512("vault-genome xcc-kem-bind v2" ‖ len32(suite) ‖ suite ‖ len32(pk) ‖ pk ‖ len32(N) ‖ N)`;
     an answer that names a suite is verified under `C₂`, an answer
     without one under the v1 challenge. A suite label swapped in
     transit changes `C₂`, and genuine Evidence no longer verifies — the
     same argument as for the key.
   - `KeyReleaseToken` schema 2: `WrappedKey.suite`; a schema-1 token
     means `x25519-kem-v1`. `SchemaVersionMax` and `Current` move to 2,
     `Min` stays 1.
   - Escrow: `vault-genome/key-escrow/v2`, `escrow-recovery/v2` and
     `sealed-escrow-key/v2` carry `suite`; the v1 documents are read as
     `x25519-kem-v1`. Escrow key files: a P-384 key is a PKIX PEM as
     X25519's is today; an ML-KEM or hybrid key is a PEM block
     `VAULT GENOME HPKE PUBLIC KEY` (and `… PRIVATE KEY`) whose headers
     name the suite and whose body is the RFC 9180 serialization, since
     PKIX has no form for them. `acpctl escrow keygen --suite` writes
     them; `genome seal --escrow-to` reads the suite from the key file.
   - The audit payloads: `delivery_mode` of `KindKeyReleaseAuthorized`
     becomes the suite id, and `crypto_profile` is added to it, to the
     escrow events and to each daemon's `identity` output, so a record
     says under which profile a key was sealed and the two sides' records
     match suite for suite as they match key for key today.

5. **Signatures are not in this ADR.** Ed25519 remains the signature of
   every record; FIPS 186-5 approves it, and CMVP #5247 lists it. An
   ECDSA P-384 or ML-DSA option touches the audit schema and the bundle
   format, and comes with its own decision (F2b).

6. **What this keeps from ADR 0009.** The only mode is a KEM to a key the
   destination generated for that handshake and bound in its Evidence;
   no private key is ever configured; there is no symmetric wrap; the
   handshake key is single-use. Suites vary the KEM, not the mode.

## Alternatives considered

- **P-384 only, no post-quantum suite.** Closes the finding for a bank's
  auditor today and reopens it under IR 8547's 2030 deprecation and CNSA
  2.0's 2030–2033 deadlines; the hybrid and ML-KEM rows cost the same
  table entries over the same standard-library code. Rejected.
- **Keep the ECIES and add curves to it.** A second hand-rolled
  construction beside a standard the library ships, with its own
  vectors to maintain. Rejected: HPKE has published test vectors and an
  IANA registry; the product's job is to pin and record, not to design.
- **Negotiate the suite freely.** A downgrade to the weakest common suite
  is the textbook failure; the profile's list is a ceiling, and the
  refusal of an answer outside it is on the record. Rejected.
- **Make `fips` the default profile.** Most deployments of the product
  are not regulated ones, and X25519 is what SSH, TLS and the messaging
  world run on; the profile is one line of configuration, visible in
  every record. Rejected for now; the default can move with a release
  note once the FIPS build (F2c) is on record.

## Consequences

- **Compatibility.** The bundle format does not change. An escrow
  envelope of 0.1.0–0.6.1 opens under `general`; under `fips` it is
  refused by name, and the operator re-seals with `acpctl` before
  switching. A `general` source and an earlier-release destination still
  release keys (the destination answers legacy X25519, which `general`
  accepts); a `fips` source does not, by design. Both daemons move
  together for the new field, as the ledger already says of the wires.
- **Sizes.** The encapsulation grows with the suite: 32 bytes for X25519,
  97 for P-384, 1088 for ML-KEM-768, 1665 for MLKEM1024-P384 (RFC 9180
  §7.1; draft-ietf-hpke-pq-05 §8); tokens and envelopes grow by that and
  nothing else. One encapsulation per DEK or handshake makes the cost
  invisible.
- **What the product can then say.** Approved key establishment is
  available and recorded per deployment; the validated-module claim
  comes with F2c — the `GOFIPS140=v1.0.0` build run under
  `fips140=only` on the hardware kits, which fails any path that still
  reaches a non-approved primitive, and a second set of release binaries
  and images built that way.
- **Evidence.** Unit: the standard library's own RFC 9180 vectors cover
  the KEMs; the product's tests cover the suite registry, the profile
  lists, every refusal (a suite outside the list, a legacy answer under
  `fips`, a key of the wrong length for its suite, a suite label swapped
  under the v2 challenge), the golden files of v1 envelopes and tokens
  still opening under `general`, and `TestCoordinateRestore_DefectB_…`
  replayed per suite. Live: `test/integration/crosscloud_test.go` per
  profile. Hardware: `scripts/hardware-test/failover-tdx` (cross-cloud
  delivery, SEV-SNP authority to a TDX destination) and
  `scripts/hardware-test/authority-loss` (escrow and recovery) under each
  profile's default suite, their evidence in the tree before the
  implementation is offered for review.
- **Documents.** `docs/compliance/banking.md` §6 cryptography rows and
  §9 F2; the compatibility ledger; the configuration reference and the
  escrow runbook; `kms/doc.go`, whose "see also" names a doctrine file
  the tree no longer has (`bootstrap-contracts.md`) — corrected with the
  implementation.

## Implementation notes

- **Cross-cloud (2026-10-21).** The contracts' signatures cover the
  canonical JSON of the whole structure, re-serialized by the verifier
  (`crypto.CanonicalJSON`): a field added to the handshake request or
  the token is not verifiable by a daemon of an earlier release, so a
  mixed pair cannot work whatever the destination answers. The
  implementation therefore does not carry the "accepted only where the
  list has it" path of Decision 3 for an answer without a suite: a
  request that names no suite (schema 1) is refused by the destination,
  an answer that names none is refused by the source, both on the
  record, and the ledger's rule that both daemons move together covers
  the upgrade. `x25519-kem-v1` stays a reader for the escrow documents
  only.
- **Escrow (2026-10-21).** The escrow and recovery keys are
  `escrow.PrivateKey`/`PublicKey` values that carry their suite; the v2
  envelope, sealed key and recovery documents name it (`suite`, and
  `recovery_suite` for the recovery key's), and each opens only under
  it; the v1 documents open as before, through the ECIES, with an
  X25519 key. Key files: PKIX "PUBLIC KEY" for X25519 and P-384, the
  block `VAULT GENOME HPKE PUBLIC KEY` with a `Suite` header for the
  keys PKIX has no form for; a private key is `VAULT GENOME HPKE
  PRIVATE KEY` with the same header, and the raw 32-byte X25519 file of
  an earlier release still reads. The key tag of an X25519 key is the
  tag earlier releases gave it (SHA-256 of the same 32 bytes).

## References

RFC 9180 (HPKE) §7.1–7.3; draft-ietf-hpke-pq-05 §3, §4, §8; the IANA HPKE
registries; NIST SP 800-56A Rev. 3, SP 800-56C Rev. 2 §2, SP 800-186,
SP 800-227 §4.6, FIPS 203, FIPS 186-5, NIST IR 8547 ipd; CMVP certificate
#5247 and its security policy; ASC X9 SD-34 (2025); NSA, "Announcing the
Commercial National Security Algorithm Suite 2.0" (2022-09-07) and its
FAQ; Go: `crypto/hpke`, `crypto/mlkem`, `crypto/fips140` of Go 1.27.3 and
the FIPS 140-3 documentation at go.dev. Each is held byte for byte in the
project library with its hash.

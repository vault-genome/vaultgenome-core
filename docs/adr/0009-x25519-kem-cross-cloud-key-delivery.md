# ADR 0009: X25519 KEM for Cross-Cloud DEK Delivery (closes defect b)

**Status:** Accepted — implemented in both daemons (2026-09-14)
**Date:** 2026-09-14
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Amends:** ADR 0006 (cross-cloud KMS-mediated restore), §"Threat Model" points 2, 4 and 5

---

## Context

Phase 4 delivered data-encryption keys (DEKs) across clouds by sealing each DEK
under a symmetric key *derived from the destination's verified measurement*
(`SimulatedKeyWrapper`: `key = SHA-256(label ‖ destination_measurement)`). The
honest-reference audit flagged this as **defect (b)**: the security argument
requires the measurement to be secret to anyone but the destination TEE, but
measurements are **public reference values** — they are published so verifiers
can pin them, and the `KeyReleaseToken` itself carries one. Anyone who read a
token in transit could derive the wrap key and recover the DEKs. ADR 0006
§"Threat Model" points 4–5 were therefore not met.

A first version of this ADR added an X25519 KEM to the library but left three
things open: the destination's public key was supplied by the operator in the
request rather than presented in the handshake, one key served every handshake,
and both deployed daemons (`sagvd crosscloud-restore`, `acp-bootstrap`) still
used the symmetric wrap. This revision closes all three.

## Decision

DEKs cross clouds **only** as an X25519 key encapsulation (ECIES: ephemeral
X25519 + HKDF-SHA256 + AES-256-GCM, `kms.X25519KeyWrapper` /
`X25519KeyUnwrapper`) to a key the destination TEE generated **for that
handshake** and bound into its Evidence.

### Protocol

1. The source authority signs a `CrossCloudHandshakeRequest` carrying a fresh
   nonce `N` (≥ 16 bytes) and sends it to the destination.
2. The destination verifies the authority's signature, then generates an X25519
   key pair `(sk, pk)` in memory, keyed by the request ID, and quotes over the
   **key-binding challenge**

   ```
   C = SHA-512("vault-genome xcc-kem-bind v1" ‖ len32(pk) ‖ pk ‖ len32(N) ‖ N)
   ```

   It answers with the Evidence, `pk`, and a measurement hint.
3. The source rejects `pk` unless it is a 32-byte X25519 key that is not a
   low-order point, recomputes `C` from the `pk` it received and its own `N`,
   and verifies the Evidence **under `C`** with the verifier registered for the
   destination's TEE family. That single check proves a genuine TEE, the
   attested measurement, freshness, and that `pk` is the TEE's own: a `pk`
   swapped in transit changes `C`, so genuine Evidence no longer verifies.
4. Only then does the allow-list policy run on the verified measurement, and
   only on approval is each DEK encapsulated to `pk`. The token's AAD binding
   (`SHA-256(TokenID ‖ measurement ‖ KeyID)`) is unchanged.
5. The destination takes `sk` out of its table by the token's `RequestID`
   (single use, whatever happens next), checks that the token's `DecisionID` is
   the handshake's, opens each DEK, registers it, and zeroizes `sk`.

### Why the challenge, not a TEE-specific REPORT_DATA layout

Every `tee.Verifier` in the tree (simulated, SEV-SNP, SGX via DCAP and via
Azure, Nitro) already checks that Evidence was produced for the challenge it is
given. Quoting over `C` turns that existing freshness check into the key binding
for every TEE family at once, with no per-vendor binding code. The earlier SEV-SNP-only binder
(`REPORT_DATA == SHA-512(pk ‖ N)`) was retired: the product's own producers hash
their challenge into REPORT_DATA, so a raw-layout binder would have rejected the
product's genuine reports. (The standalone hardware probe under
`scripts/hardware-test/gcp-sev-snp/keybind-evidence/` demonstrates the raw layout
on real silicon and is verified by its own script.)

The label and the 64-byte length keep `C` apart from every other value the
system asks a TEE to quote over — the Return Path's challenges are 32-byte
SHA-256 transcripts under their own labels — so a quote obtained through one
protocol can never satisfy the other.

### No fallback

The measurement-derived symmetric wrap is **deleted**, not deprecated: there is
no `Wrapper`/`Unwrapper` option on the Coordinator or the Receiver, and a
destination that presents no attested key receives nothing. The destination
generates its keys itself; no private key is ever configured, stored or
transmitted.

### Wire changes

- `HandshakeResponse` gains `recipient_public_key` (the HTTP handshake answer
  and `kms.HandshakeResponse`).
- `CoordinationResult` and the `KindCrossCloudAttestationVerified` /
  `KindKeyReleaseAuthorized` audit payloads gain `recipient_key_sha256`;
  the latter also records `delivery_mode = "x25519-kem-v1"`. The destination
  logs the same digest when it answers the handshake, so the two sides'
  records can be matched key for key.
- Cross-cloud measurements are carried whole — 32, 48 or 64 bytes — in the
  token, the handshake request, the allow-list policy and the `sagvd` loaders
  (the last 32-byte assumptions left over from defect (a), ADR 0007).

## Consequences

- **Defect (b) is closed in the shipping daemons.** Intercepting a token — even
  together with the measurement it names — yields nothing: the DEKs are sealed to
  a key that exists only inside the destination TEE, only until the token uses
  it. `TestCoordinateRestore_DefectB_TokenPlusMeasurementRevealsNothing` replays
  the old derivation (and the measurement as an X25519 key) against a real token
  and must fail to open anything.
- **Forward secrecy per restore.** A later compromise of the destination host, or
  of another handshake's key, does not expose an earlier restore's DEKs.
- **Replay and substitution are refused by construction** (ADR 0006 threat
  points 2, 4, 5): a replayed handshake cannot replace an outstanding key (the
  request ID is refused while outstanding); a replayed or forged token finds no
  key (single use, 5-minute TTL, signature checked before the key is touched); a
  key substituted in transit fails attestation; a degenerate (low-order) key is
  refused before anything is recorded as verified.
- **Evidence** — unit: `internal/vault/kms/coordinator_test.go` (substituted key,
  unbound Evidence, withheld key, low-order key, audit digest, defect-(b)
  regression), `internal/bootstrap/crosscloud/receiver_test.go` (per-handshake
  keys, replay, single use, expiry, decision binding, forged token cannot burn a
  key, 16 concurrent restores under `-race`); each security check was removed in
  turn to confirm a test fails. Live: `test/integration/crosscloud_test.go` runs
  `sagvd crosscloud-restore` against a real `acp-bootstrap` process over TLS 1.3
  with client certificates and a bearer token, and checks that both processes
  record the same recipient key; an unlisted destination and an impostor TEE
  receive nothing.
- **On real hardware (2026-09-14):** with the SEV-SNP producer wired through
  configfs-tsm, the shipping `sagvd crosscloud-restore` released a DEK to
  `acp-bootstrap` running on a GCP SEV-SNP Confidential VM, verifying the chip's
  Evidence under the key-binding challenge; the same guest, left off the
  allow-list, was refused (`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/`).
  The protocol needed no change — the SEV-SNP verifier's REPORT_DATA check on
  the challenge is the binding.

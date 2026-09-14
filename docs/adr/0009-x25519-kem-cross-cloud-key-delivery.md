# ADR 0009: X25519 KEM for Cross-Cloud DEK Delivery (closes defect b)

**Status:** Accepted
**Date:** 2026-09-14
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Amends:** ADR 0006 (cross-cloud KMS-mediated restore), §"Threat Model" point 5

---

## Context

Phase 4 delivered data-encryption keys (DEKs) across clouds by sealing each DEK
under a symmetric key *derived from the destination's verified measurement*
(`SimulatedKeyWrapper`: `key = HKDF(label ‖ destination_measurement)`). The
honest-reference audit flagged this as **defect (b)**: the security argument
requires the measurement to be secret to anyone but the destination TEE, but
measurements are **public reference values** (they are published so verifiers can
pin them). An attacker who intercepts the `KeyReleaseToken` and knows the
destination measurement — which they can — can derive the same wrap key and
recover the DEKs. ADR 0006 §"Threat Model" points 4–5 were therefore not met.

## Decision

Replace the symmetric measurement-derived wrap with an **X25519 key-encapsulation
mechanism** (ECIES: ephemeral X25519 + HKDF-SHA256 + AES-256-GCM), already
implemented as `kms.X25519KeyWrapper` / `X25519KeyUnwrapper` (kem.go).

- The destination generates an X25519 keypair **inside its TEE** during the
  handshake and **binds the public key to its attestation**: the Evidence's
  `REPORT_DATA = hash(public_key ‖ handshake_nonce)` (the same binding proven
  against real AMD SEV-SNP hardware in the honest-reference work). The private
  key never leaves the TEE.
- The destination presents the attested public key to the source (handshake
  response). The source Coordinator, after verifying the Evidence **and** that
  `REPORT_DATA` commits to `(public_key ‖ nonce)`, encapsulates each DEK to that
  public key. `CoordinationRequest.RecipientPublicKey` carries it.
- The `KeyReleaseToken`'s `WrappedKey.Ciphertext` is the KEM output
  (`ephPub(32) ‖ nonce(12) ‖ AES-GCM ciphertext`). The destination decapsulates
  with its TEE-held private key (`Receiver.RecipientPrivateKey`).

**Confidentiality now rests on the destination TEE holding the private key, not
on the measurement being secret.** The measurement is still checked
(`token.DestinationMeasurement == local measurement`) as a policy gate — defence
in depth — and the AAD binding (`SHA-256(TokenID ‖ measurement ‖ KeyID)`) is
unchanged, so a token cannot be replayed against a different context.

### Interface

The `KeyWrapper` / `KeyUnwrapper` interfaces are unchanged in shape — their second
argument is now named `keyMaterial` (the destination measurement for the
simulation-only symmetric wrapper, the X25519 public/private key for the KEM). The
Coordinator and Receiver select the KEM path when `RecipientPublicKey` /
`RecipientPrivateKey` are set, and fall back to the legacy symmetric path
otherwise, so existing simulation tests are unaffected.

## Consequences

- Defect (b) is closed at the protocol level: intercepting the token no longer
  yields the DEKs, because the attacker lacks the TEE-held private key.
- `internal/bootstrap/crosscloud/kem_roundtrip_test.go` proves it end to end
  through the receiver's real code: a DEK encapsulated to the attested public key
  is decapsulated and registered; a receiver holding the wrong private key is
  rejected with a `CategoryIntegrity` error.
- **Open (needs a hardware run):** wiring the `REPORT_DATA = hash(pubkey ‖ nonce)`
  binding check into the Coordinator's Evidence-verification step against a real
  SEV-SNP/Nitro report (the primitive and the offline verification already exist
  from the honest-reference SEV-SNP work); and rotating the in-TEE keypair per
  handshake. Until then the binding is specified and enforced by construction in
  the test, not yet verified against live Evidence in the Coordinator.
- The symmetric `SimulatedKeyWrapper` remains for simulation/testing only, clearly
  labelled; production deployments MUST set the KEM fields.

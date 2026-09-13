# Real SEV-SNP attestation with a TEE-bound key (honest-reference)

Genuine, independently-verifiable AMD SEV-SNP attestation captured on a live Google
Confidential VM (`n2d-standard-2`, AMD Milan), **production mode (not debug)**, in which
the guest generated an **X25519 key pair inside the enclave** and bound its public key
into the attestation freshness field:

    REPORT_DATA = SHA-512( x25519_pub_DER || challenger_nonce )

The private key never left the guest (the VM was destroyed after capture).

## What this proves (verified by `vg_verify.py`, KDS chain fetched independently)
1. `REPORT_DATA == SHA-512(pubkey || nonce)` — the key is bound to *this* attestation. **PASS**
2. Report ECDSA-P384 signature under the VCEK. **PASS**
3. VCEK → ASK → **ARK-Milan** (chain fetched from AMD KDS by the verifier, not the guest). **PASS**
4. VCEK `hwID` == report `CHIP_ID`. **PASS**

Run: chip `e8a8278ccf9ce48f…`, measurement (48-byte SHA-384)
`0e017d2fba7c4964…`, us-central1-b, 2026-09-13. Reproduce with `probe-vaultgenome.sh`
(startup script) + `vg_verify.py <run-dir>`.

## What this does NOT yet prove (honest scope)
- The model workload is **not** yet run inside this TEE (attestation + key-binding layer only).
- This capture is produced by a standalone probe; wiring it into the product's
  `gcp_sev_snp` adapter (replacing the Phase-2 stub) is the next milestone.
- It is the honest basis for replacing the symmetric cross-cloud wrap key
  (see `internal/vault/kms/wrapper.go`) with encapsulation to this TEE-bound public key.

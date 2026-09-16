# A genuine Intel TDX quote from a GCP Trust Domain

The raw material the TDX producer and verifier
(`internal/shared/tee/gcp_tdx*.go`, ADR 0018) were built and are tested
against: two TDX quotes with caller nonces, taken through the kernel's
configfs-tsm interface on a Google Cloud Confidential VM with Intel TDX,
and the public Intel PCS documents the verifier evaluates them with.

`run.sh <project> [zone]` boots a `c3-standard-4` (`--confidential-compute-type
TDX`, Ubuntu 24.04) whose startup script (`cvm-tdx-capture.sh`) asks
`/sys/kernel/config/tsm/report` (provider `tdx_guest`) for a quote with a
64-byte `inblob` — `SHA-256("vault-genome tdx capture <stamp> challenge N")`
then 32 zero bytes, the shape the producer uses — twice with different
nonces, records what the guest sees of itself (kernel, `dmesg`,
`/dev/tdx_guest`, CPU flags) and parses one quote by offsets for the
record; `pcs_fetch.py` then splits the quote's PCK certificate chain, reads
the FMSPC from the PCK certificate's SGX extension and fetches from Intel
PCS the TCB info for it, the QE identity (each with its issuer chain from
the response header), the Intel SGX Root CA and its CRL, and the PCK CRL.
The VM and its bucket are deleted at the end.

Everything captured is public by construction: a quote is a signed
statement about the guest, the PCK chain and PCS documents are Intel's
published certificates and documents. No key, seed or token is produced or
kept.

## Capture `20260916T031937Z` (evidence/20260916T031937Z)

`us-central1-a`, `c3-standard-4`, kernel `7.0.0-1011-gcp`; `dmesg`: `tdx:
Guest detected`, `Attributes: SEPT_VE_DISABLE`, `Memory Encryption Features
active: Intel TDX`; `/proc/cpuinfo` model name `Intel TDX`, flag
`tdx_guest`.

What the quote says (`q1.layout.txt`, read by the spec's offsets):

| Field | Value |
|---|---|
| quote | 8 000 bytes, version 4, attestation key type 2 (ECDSA-P256), TEE type `0x81` (TDX), QE vendor id `939a7233…0607` (Intel) |
| TEE_TCB_SVN | `0f010a00…` — TDX module `TDX_01`, SVN 15 |
| MRSEAM / MRSIGNERSEAM | `ab62561a…7f6b` / all zero (Intel's module) |
| TDATTRIBUTES / XFAM | `0000001000000000` (SEPT_VE_DISABLE; **no DEBUG**) / `e702060000000000` |
| MRTD | `c1ee9c16…70a5` |
| MRCONFIGID / MROWNER / MROWNERCONFIG | zero / `aecbe5ab…b40e` / zero |
| RTMR0 / RTMR1 / RTMR2 / RTMR3 | `60d411d6…77b6` / `c7183cb4…f287` / `90e31c74…5c90` / zero |
| REPORTDATA | the caller's nonce, byte for byte (`q1.meta.txt`) |
| signature data | 4 299 bytes: QE certification data type 6, QE authentication data 32 bytes, inner certification data type 5 (PCK chain, 3 PEM certificates, 3 677 bytes) |

The two quotes differ only in REPORTDATA (`diff q1.layout.txt
q2.layout.txt`): MRTD and the RTMRs are the same for the life of the guest,
which is what a pin needs.

Intel's word on the platform (`pcs.json`, `tcb-info.json`,
`qe-identity.json`): FMSPC `00806f050000`; TCB info v3, evaluation data
number 20, issued 2026-09-16T03:00:02Z, next update 2026-10-16, 6 TCB
levels, the highest (`tcbDate` 2025-08-13, PCE SVN 11, TDX components
`5,0,9,0,…`) `UpToDate`; TDX module identities `TDX_01` (ISV SVN ≥ 11
`UpToDate`) and `TDX_03`; QE identity `TD_QE` v2, ISVPRODID 2, ISV SVN ≥ 4
`UpToDate`. The verifier rates this platform, its TDX module and its QE
**UpToDate** (`TestGCPTDX_VerifiesTheCapturedQuote` and the TCB tests in
[`gcp_tdx_test.go`](../../../../internal/shared/tee/gcp_tdx_test.go)).

The chain: the quote's attestation key over bytes `[0, 632)`, the PCK leaf
over the QE report, the QE report's REPORTDATA = `SHA-256(attestation key ‖
authentication data) ‖ zeros`, PCK leaf → Intel SGX PCK Platform CA →
Intel SGX Root CA (`intel-sgx-root-ca.pem`, valid to 2049; the same
certificate is pinned in the verifier). Checksums: `cd
evidence/20260916T031937Z && grep -v ' sha256sums.txt$' sha256sums.txt |
shasum -a 256 -c`.

## What the tests do with it

Every test in `gcp_tdx_test.go` runs offline against this capture with the
PCS documents served from the evidence directory as the verifier's cache:
the genuine quote verifies under the pinned root at the captured time; the
same quote with another root, the DEBUG bit flipped, a byte of the TD
report changed, a wrong nonce, a measurement not on the list, an edited TCB
level in the cached document, a document past its next update, or a stale
cache with no network, does not. The producer's round trip runs against a
fake configfs-tsm that serves the captured quotes.

## Reproduce

```bash
scripts/hardware-test/gcp-tdx/capture/run.sh <gcp-project>        # ~5 minutes of c3-standard-4
go test -count=1 -run 'GCPTDX|TDX' ./internal/shared/tee/
```

# Vault Genome — SGX Quote Binding

A minimal Open Enclave program plus standalone Intel DCAP verifier that
together implement the Vault Genome attestation spec on Intel SGX:

> **REPORT_DATA = SHA-512(vaultgenome-payload-manifest.json)**

The package solves a concrete problem: `oeutil generate-evidence` in
Open Enclave 0.19.x dropped the `--in-data` flag, so there's no longer
a one-liner CLI for getting an SGX quote with custom 64-byte
report_data. This program restores that capability.

## Layout

```
sgx-quote-binding/
├── binding.edl            # Single ECALL: pass 64 bytes, get back an OE-wrapped report
├── enc/
│   ├── enc.c              # Enclave: oe_get_report(REMOTE_ATTESTATION, report_data, ...)
│   └── enc.conf           # Signing config (Debug=1, ProductID=1, SecurityVersion=1)
├── host/
│   ├── host.c             # Host: read report-data.bin, call ECALL, write quote.bin + .oe
│   └── verify-quote.c     # Standalone Intel-DCAP chain verifier
├── Makefile               # Build via pkg-config oeenclave/oehost-gcc
└── README.md
```

## Build

On any Azure DCsv3 SGX VM that has been bootstrapped via
`scripts/01-bootstrap-vm.sh`:

```bash
cd ~/sgx-quote-binding   # uploaded by orchestrate-cohort-vm.sh
make
```

Outputs:

| Artifact | Purpose |
|---|---|
| `binding_enc.signed` | Signed enclave (oesign output). MRENCLAVE = identity of the binding code. |
| `binding_host` | Host program: `./binding_host binding_enc.signed report-data.bin quote.bin` |
| `verify_quote` | Standalone Intel-DCAP chain verifier: `./verify_quote quote.bin [expected-report-data.bin]` |

## Generate a workload-bound quote

```bash
# 1. Compute SHA-512 of the workload manifest (any 64-byte hash works).
sha512sum manifest.json | awk '{print $1}' > report-data.hex
xxd -r -p report-data.hex report-data.bin
test "$(stat -c %s report-data.bin)" = "64"   # exact 64 bytes required

# 2. Ask the SGX hardware to sign over those 64 bytes via EREPORT.
./binding_host binding_enc.signed report-data.bin quote.bin
# → writes:  quote.bin       (raw SGX quote v3, ~5 KB)
#            quote.bin.oe    (OE-wrapped form, +16 bytes)

# 3. Validate the chain Quote → PCK → Intel SGX Root CA, and check
#    REPORT_DATA matches the manifest hash:
./verify_quote quote.bin report-data.bin
```

`verify_quote` emits four useful blocks:

* SGX quote inspection (MRENCLAVE / MRSIGNER / ISV_PROD_ID / ISV_SVN /
  REPORT_DATA actually present in the quote).
* Comparison with the expected REPORT_DATA — the workload-binding check.
* Chain verification result from `sgx_qv_verify_quote()` — the canonical
  Intel verifier path.
* A clean exit code: `0` = chain valid AND binding intact, `2` = chain
  invalid, `3` = chain valid but binding broken.

## Why a custom enclave (instead of `oeutil generate-evidence`)

`oeutil generate-evidence -f sgx_ecdsa` in OE 0.19+ no longer accepts
`--in-data`. With `oe_get_evidence(SGX_ECDSA)` the lower 32 bytes of
report_data are auto-set to `SHA-256(custom_claims)` and the upper 32
bytes are zeroed by the OE runtime — there is no way to get a single
64-byte hash into report_data.

`oe_get_report(OE_REPORT_FLAGS_REMOTE_ATTESTATION, report_data, 64,
...)` (legacy API, still supported in 0.19) hands the 64 bytes through
to `EREPORT` verbatim, which is what the Vault Genome attestation spec
requires.

## Why a standalone verifier

Two reasons:

1. **Canonical Intel path.** `sgx_qv_verify_quote()` from
   `libsgx-dcap-quote-verify` is what every commercial SGX verifier
   uses (Microsoft Azure Attestation, Intel Trust Authority, AWS Nitro
   Enclaves' SGX adapter, etc.). Running it ourselves removes
   "tooling dependency" from the trust argument.

2. **Independent of OE runtime quirks.** The OE-wrapped form is also
   saved (`quote.bin.oe`) for `oeutil verify-evidence -f
   legacy_report_remote`. Two independent verifiers agreeing on the
   same chain is the audit-grade outcome.

## Reproducibility

Anyone with access to a fresh DCsv3 SGX VM can:

```bash
cd /opt/openenclave/share/openenclave/samples
# (the binding/ subtree above is small enough to copy in by hand)
make            # standard OE sample build
./binding_host ...
./verify_quote ...
```

— and get the same chain validation against Intel's hardware root of
trust without trusting any Vault Genome–specific tooling.

// SPDX-License-Identifier: AGPL-3.0-or-later
//
// verify-quote.c — Vault Genome Intel DCAP chain verifier.
//
// Validates a raw SGX_ECDSA quote v3 against the Intel SGX Root CA via
// libsgx-dcap-quote-verify (the Intel-blessed local verifier),
// using az-dcap-client's libdcap_quoteprov.so to fetch PCK collateral
// from the Azure-hosted Intel cache.
//
// Reports:
//   * MRENCLAVE, MRSIGNER, ISV_PROD_ID, ISV_SVN
//   * The 64-byte REPORT_DATA actually present in the quote
//   * Whether REPORT_DATA matches a caller-provided expected value
//     (Vault Genome convention: SHA-256(manifest) || 32 zero bytes
//      for SGX/MAA; SHA-512(manifest) for SEV-SNP — file just needs
//      to be 64 bytes, semantics are documented in 02b script).
//   * Cryptographic chain Quote → PCK certificate → Intel SGX Root CA
//     via sgx_qv_verify_quote(). NOTE: this local-host call is known
//     to surface SGX_QL_NO_QUOTE_COLLATERAL_DATA (0xE03A) on Azure
//     when az-dcap-client and libsgx-dcap-quote-verify versions
//     skew — Microsoft Azure Attestation (02f script) walks the same
//     chain on Microsoft's side and is the chain of record.
//
// Usage:
//   ./verify-quote <quote.bin> <expected-report-data.bin>

#include <sgx_dcap_quoteverify.h>
#include <sgx_quote_3.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int read_file(const char* path, uint8_t** out_buf, size_t* out_size)
{
    FILE* fp = fopen(path, "rb");
    if (!fp) { perror(path); return -1; }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return -1; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return -1; }
    uint8_t* buf = (uint8_t*)malloc((size_t)sz);
    if (!buf) { fclose(fp); return -1; }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) { free(buf); fclose(fp); return -1; }
    fclose(fp);
    *out_buf = buf;
    *out_size = (size_t)sz;
    return 0;
}

static void hex(const uint8_t* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        printf("%02x", b[i]);
}

int main(int argc, char** argv)
{
    if (argc < 2 || argc > 3)
    {
        fprintf(stderr,
            "Usage: %s <quote.bin> [expected-report-data.bin]\n",
            argv[0]);
        return 1;
    }

    uint8_t* quote = NULL;
    size_t   quote_size = 0;
    if (read_file(argv[1], &quote, &quote_size) != 0)
        return 1;

    if (quote_size < sizeof(sgx_quote3_t))
    {
        fprintf(stderr, "ERROR: quote too small (%zu < %zu)\n",
                quote_size, sizeof(sgx_quote3_t));
        free(quote);
        return 1;
    }

    sgx_quote3_t* q = (sgx_quote3_t*)quote;
    const sgx_report_body_t* body = &q->report_body;

    printf("=== SGX quote v3 inspection ===\n");
    printf("quote_size:     %zu bytes\n", quote_size);
    printf("header.version: %u\n", (unsigned)q->header.version);
    printf("att_key_type:   %u (2 = ECDSA-P256)\n", (unsigned)q->header.att_key_type);
    printf("MRENCLAVE:      "); hex(body->mr_enclave.m, 32); printf("\n");
    printf("MRSIGNER:       "); hex(body->mr_signer.m, 32); printf("\n");
    printf("ISV_PROD_ID:    %u\n", (unsigned)body->isv_prod_id);
    printf("ISV_SVN:        %u\n", (unsigned)body->isv_svn);
    printf("REPORT_DATA:    "); hex(body->report_data.d, 64); printf("\n");

    int report_data_match = -1;
    if (argc == 3)
    {
        uint8_t* expected = NULL;
        size_t   expected_size = 0;
        if (read_file(argv[2], &expected, &expected_size) != 0)
        {
            free(quote);
            return 1;
        }
        if (expected_size != 64)
        {
            fprintf(stderr,
                "ERROR: expected report-data must be 64 bytes (got %zu)\n",
                expected_size);
            free(expected);
            free(quote);
            return 1;
        }
        report_data_match = (memcmp(body->report_data.d, expected, 64) == 0) ? 1 : 0;
        printf("EXPECTED:       "); hex(expected, 64); printf("\n");
        printf("REPORT_DATA == expected (manifest binding): %s\n",
               report_data_match ? "YES (workload binding verified)"
                                 : "NO (binding broken)");
        free(expected);
    }

    // ----- Chain validation: Quote → PCK → Intel SGX Root CA -----
    printf("\n=== chain verification (libsgx-dcap-quote-verify) ===\n");

    uint32_t supp_data_size = 0;
    if (sgx_qv_get_quote_supplemental_data_size(&supp_data_size) != SGX_QL_SUCCESS)
    {
        fprintf(stderr,
            "WARNING: sgx_qv_get_quote_supplemental_data_size failed; using 0.\n");
        supp_data_size = 0;
    }
    uint8_t* supp_data = supp_data_size > 0 ? (uint8_t*)calloc(1, supp_data_size) : NULL;

    time_t   current_time = time(NULL);
    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t qv_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    // Explicit collateral fetch via the unified `tee_*` API. Direct
    // sgx_qv_verify_quote(..., collateral=NULL, ...) works with Intel's
    // default QPL but races with az-dcap-client across libsgx-dcap-
    // quote-verify versions where the auto-fetch contract differs. The
    // tee_qv_get_collateral path is the version-tolerant fix.
    uint8_t* collateral_buf = NULL;
    uint32_t collateral_size = 0;
    quote3_error_t coll_r = tee_qv_get_collateral(
        quote, (uint32_t)quote_size,
        &collateral_buf, &collateral_size);
    if (coll_r != SGX_QL_SUCCESS || !collateral_buf || collateral_size == 0)
    {
        fprintf(stderr,
            "✗ tee_qv_get_collateral failed: 0x%04x (size=%u)\n",
            (unsigned)coll_r, collateral_size);
        free(quote);
        if (supp_data) free(supp_data);
        return 2;
    }
    printf("collateral fetched:            %u bytes via tee_qv_get_collateral\n",
           collateral_size);

    quote3_error_t r = sgx_qv_verify_quote(
        quote, (uint32_t)quote_size,
        (const sgx_ql_qve_collateral_t*)collateral_buf,
        current_time,
        &collateral_expiration_status,
        &qv_result,
        NULL,                          // qve_report_info — NULL = host-side
        supp_data_size,
        supp_data);

    tee_qv_free_collateral(collateral_buf);

    if (r != SGX_QL_SUCCESS)
    {
        fprintf(stderr,
            "✗ sgx_qv_verify_quote returned 0x%04x — chain NOT validated\n",
            (unsigned)r);
        free(quote);
        if (supp_data) free(supp_data);
        return 2;
    }

    const char* qv_str = "UNKNOWN";
    int chain_ok = 0;
    switch (qv_result)
    {
        case SGX_QL_QV_RESULT_OK:
            qv_str = "OK"; chain_ok = 1; break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
            qv_str = "CONFIG_NEEDED (chain valid; platform config noted)"; chain_ok = 1; break;
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
            qv_str = "OUT_OF_DATE (chain valid; TCB needs update)"; chain_ok = 1; break;
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
            qv_str = "OUT_OF_DATE_CONFIG_NEEDED (chain valid)"; chain_ok = 1; break;
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            qv_str = "SW_HARDENING_NEEDED (chain valid; advisory)"; chain_ok = 1; break;
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            qv_str = "CONFIG_AND_SW_HARDENING_NEEDED (chain valid)"; chain_ok = 1; break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
            qv_str = "INVALID_SIGNATURE"; break;
        case SGX_QL_QV_RESULT_REVOKED:
            qv_str = "REVOKED"; break;
        case SGX_QL_QV_RESULT_UNSPECIFIED:
            qv_str = "UNSPECIFIED"; break;
        default:
            break;
    }

    printf("verification result:           %s (0x%04x)\n",
           qv_str, (unsigned)qv_result);
    printf("collateral expiration status:  %u (0 = within validity window)\n",
           (unsigned)collateral_expiration_status);

    if (chain_ok)
    {
        printf("✓ Quote → PCK → Intel SGX Root CA chain VALIDATED\n");
    }
    else
    {
        printf("✗ Chain validation FAILED\n");
    }

    free(quote);
    if (supp_data) free(supp_data);

    int exit_code = chain_ok ? 0 : 2;
    if (argc == 3 && report_data_match == 0)
        exit_code = 3;  // chain valid but binding broken — distinct exit code
    return exit_code;
}

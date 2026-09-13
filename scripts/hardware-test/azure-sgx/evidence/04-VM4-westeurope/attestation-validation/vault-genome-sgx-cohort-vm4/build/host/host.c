// SPDX-License-Identifier: AGPL-3.0-or-later
//
// host.c — Vault Genome SGX quote-binding host.
//
// 1. Read 64 bytes of report_data (SHA-512 of the workload manifest)
//    from disk.
// 2. Create the quote-binding enclave.
// 3. Pass the bytes to the ECALL; receive the OE-wrapped remote
//    attestation report.
// 4. Persist two artifacts:
//      <out>.oe        — full OE-wrapped report (used by oeutil verify-evidence)
//      <out>           — raw SGX quote v3 (header stripped, used by Intel DCAP tooling)
//
// The OE remote attestation report layout is:
//   bytes 0..3   — version       (uint32_t little-endian)
//   bytes 4..7   — report_type   (uint32_t)
//   bytes 8..15  — report_size   (uint64_t)
//   bytes 16..   — actual SGX quote v3
// We strip the 16-byte header to get the raw quote.

#include <openenclave/host.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "binding_u.h"

#define OE_REPORT_HEADER_SIZE 16

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

static int write_file(const char* path, const uint8_t* buf, size_t size)
{
    FILE* fp = fopen(path, "wb");
    if (!fp) { perror(path); return -1; }
    if (fwrite(buf, 1, size, fp) != size) { fclose(fp); return -1; }
    fclose(fp);
    return 0;
}

int main(int argc, const char* argv[])
{
    if (argc != 4)
    {
        fprintf(stderr,
            "Vault Genome SGX quote-binding host\n"
            "Usage: %s <enclave.signed> <report-data.bin> <out-quote.bin>\n"
            "  <enclave.signed>   Signed enclave (output of oesign).\n"
            "  <report-data.bin>  Exactly 64 bytes — SHA-512(manifest).\n"
            "  <out-quote.bin>    Raw SGX quote v3 written here;\n"
            "                     OE-wrapped report written to <out-quote.bin>.oe\n",
            argv[0]);
        return 1;
    }

    const char* enclave_path = argv[1];
    const char* report_data_path = argv[2];
    const char* quote_out_path = argv[3];

    uint8_t* report_data = NULL;
    size_t report_data_size = 0;
    if (read_file(report_data_path, &report_data, &report_data_size) != 0)
    {
        fprintf(stderr, "ERROR: cannot read %s\n", report_data_path);
        return 1;
    }
    if (report_data_size != 64)
    {
        fprintf(stderr, "ERROR: report_data must be exactly 64 bytes (got %zu)\n",
                report_data_size);
        free(report_data);
        return 1;
    }

    oe_enclave_t* enclave = NULL;
    oe_result_t result = oe_create_binding_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_AUTO,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL, 0,
        &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "oe_create_binding_enclave failed: %s\n",
                oe_result_str(result));
        free(report_data);
        return 1;
    }

    uint8_t* report_buffer = NULL;
    size_t report_buffer_size = 0;
    oe_result_t ecall_status = OE_FAILURE;

    result = get_quote_with_report_data_ecall(
        enclave,
        &ecall_status,
        report_data,
        report_data_size,
        &report_buffer,
        &report_buffer_size);

    if (result != OE_OK || ecall_status != OE_OK)
    {
        fprintf(stderr,
            "ECALL failed: oe_call=%s ecall=%s\n",
            oe_result_str(result),
            oe_result_str(ecall_status));
        oe_terminate_enclave(enclave);
        free(report_data);
        return 1;
    }

    if (report_buffer_size <= OE_REPORT_HEADER_SIZE)
    {
        fprintf(stderr,
            "ERROR: report buffer too small (%zu bytes — must contain OE header + quote)\n",
            report_buffer_size);
        free(report_buffer);
        oe_terminate_enclave(enclave);
        free(report_data);
        return 1;
    }

    char oe_report_path[1024];
    int n = snprintf(oe_report_path, sizeof(oe_report_path), "%s.oe", quote_out_path);
    if (n < 0 || n >= (int)sizeof(oe_report_path))
    {
        fprintf(stderr, "ERROR: output path too long\n");
        free(report_buffer);
        oe_terminate_enclave(enclave);
        free(report_data);
        return 1;
    }

    // Persist OE-wrapped form (oeutil verify-evidence consumes this).
    if (write_file(oe_report_path, report_buffer, report_buffer_size) != 0)
    {
        fprintf(stderr, "ERROR: cannot write %s\n", oe_report_path);
        free(report_buffer);
        oe_terminate_enclave(enclave);
        free(report_data);
        return 1;
    }

    // Persist raw SGX quote v3 (header stripped) — Intel DCAP tooling consumes this.
    size_t quote_size = report_buffer_size - OE_REPORT_HEADER_SIZE;
    if (write_file(quote_out_path, report_buffer + OE_REPORT_HEADER_SIZE, quote_size) != 0)
    {
        fprintf(stderr, "ERROR: cannot write %s\n", quote_out_path);
        free(report_buffer);
        oe_terminate_enclave(enclave);
        free(report_data);
        return 1;
    }

    printf("OK\n");
    printf("OE-wrapped report:  %s (%zu bytes)\n", oe_report_path, report_buffer_size);
    printf("Raw SGX quote v3:   %s (%zu bytes)\n", quote_out_path, quote_size);
    printf("REPORT_DATA bound:  %zu bytes (passed to oe_get_report verbatim)\n",
           report_data_size);

    free(report_buffer);
    oe_terminate_enclave(enclave);
    free(report_data);
    return 0;
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//
// enc.c — Vault Genome SGX quote-binding enclave.
//
// One ECALL: receive 64 bytes from the host (SHA-512(manifest)),
// invoke oe_get_report(REMOTE_ATTESTATION, report_data, ...) so the
// SGX hardware signs over those exact 64 bytes via EREPORT, then
// return the resulting OE-wrapped report to the host.
//
// The returned buffer is allocated in host-shared memory via
// oe_host_malloc so the host can use it after the ECALL returns.

#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>

#include "binding_t.h"

oe_result_t get_quote_with_report_data_ecall(
    const uint8_t* report_data,
    size_t report_data_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_OK;
    uint8_t* enclave_report = NULL;
    size_t enclave_report_size = 0;
    uint8_t* host_report = NULL;

    if (!report_data || report_data_size != 64 ||
        !report_buffer || !report_buffer_size)
    {
        return OE_INVALID_PARAMETER;
    }

    *report_buffer = NULL;
    *report_buffer_size = 0;

    // Ask the SGX hardware (via OE runtime + DCAP quoting enclave) to
    // produce an SGX_ECDSA quote v3 with REPORT_DATA = the bytes the
    // host gave us. The output is an OE-wrapped remote attestation
    // report (16-byte oe_report_header_t || SGX quote bytes).
    result = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        report_data,
        report_data_size,
        NULL,  // opt_params
        0,
        &enclave_report,
        &enclave_report_size);

    if (result != OE_OK)
        goto exit;

    // Copy into host-shared memory so the host can read it after we return.
    host_report = (uint8_t*)oe_host_malloc(enclave_report_size);
    if (!host_report)
    {
        result = OE_OUT_OF_MEMORY;
        goto exit;
    }
    memcpy(host_report, enclave_report, enclave_report_size);

    *report_buffer = host_report;
    *report_buffer_size = enclave_report_size;
    host_report = NULL;  // ownership transferred to host

exit:
    if (enclave_report)
        oe_free_report(enclave_report);
    if (host_report)
        oe_host_free(host_report);
    return result;
}

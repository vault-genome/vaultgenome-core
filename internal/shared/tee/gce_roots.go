// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Google's root for the vTPM of a Compute Engine instance, pinned: the
// "EK/AK CA Root" that issues, through an intermediate, the certificates of
// every vTPM's endorsement and attestation keys (ADR 0037). The bytes are
// the certificate the intermediate's authority-information URL served on
// 2026-10-24, and the same certificate Google ships in its open-source
// verifier (github.com/google/go-tpm-tools, server/ca-certs/
// gcp_ek_ak_ca_root.crt): SHA-256 fingerprint
// 59:47:59:59:4B:9B:61:52:4F:6C:8E:F6:68:F7:17:7F:7B:90:66:BC:06:74:F2:F4:9F:E9:E0:52:BE:78:BE:B2.
// The intermediates rotate (the one in go-tpm-tools is v3; instances
// created on 2026-10-24 chain through a newer one), so they ride with the
// evidence and only the root is pinned. An operator may pin others through
// the verifier's configuration.

// GCEEKAKRootPEM is Google's EK/AK CA Root.
const GCEEKAKRootPEM = `-----BEGIN CERTIFICATE-----
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
av16U4E=
-----END CERTIFICATE-----
`

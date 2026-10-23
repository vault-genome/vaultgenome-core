#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Makes the CMS vectors with OpenSSL 3 — an implementation nobody here
# wrote — in the current directory. The key is throwaway, made for these
# vectors and used for nothing else.
set -euo pipefail
O="${OPENSSL:-openssl}"
"$O" version > openssl-version.txt
"$O" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out recipient-key.pem 2>/dev/null
"$O" req -new -x509 -key recipient-key.pem -subj "/CN=vaultgenome cms test recipient" -days 36500 \
  -addext subjectKeyIdentifier=hash -out recipient-cert.pem 2>/dev/null
"$O" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out other-key.tmp 2>/dev/null
"$O" req -new -x509 -key other-key.tmp -subj "/CN=vaultgenome cms other recipient" -days 36500 \
  -addext subjectKeyIdentifier=hash -out other-cert.pem 2>/dev/null
rm -f other-key.tmp
"$O" rand -out plain-32.bin 32
"$O" rand -out plain-4096.bin 4096
OAEP=(-keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256)
enc() { # in out cipher [recip args...]
  local in="$1" out="$2" cipher="$3"; shift 3
  "$O" cms -encrypt -binary -in "$in" "$cipher" "$@" -outform DER -out "$out"
}
# The profile KMS answers with: one recipient by subject key identifier,
# RSAES-OAEP with SHA-256 and MGF1-SHA-256, AES-256-CBC.
enc plain-32.bin   kms-profile-32.der          -aes-256-cbc -keyid -recip recipient-cert.pem "${OAEP[@]}"
enc plain-32.bin   kms-profile-32-stream.ber   -aes-256-cbc -keyid -recip recipient-cert.pem "${OAEP[@]}" -stream
enc plain-4096.bin kms-profile-4096.der        -aes-256-cbc -keyid -recip recipient-cert.pem "${OAEP[@]}"
enc plain-4096.bin kms-profile-4096-stream.ber -aes-256-cbc -keyid -recip recipient-cert.pem "${OAEP[@]}" -stream
# Outside the profile, each refused by name.
enc plain-32.bin oaep-sha1.der      -aes-256-cbc -keyid -recip recipient-cert.pem -keyopt rsa_padding_mode:oaep
enc plain-32.bin pkcs1v15.der       -aes-256-cbc -keyid -recip recipient-cert.pem
enc plain-32.bin aes128cbc.der      -aes-128-cbc -keyid -recip recipient-cert.pem "${OAEP[@]}"
enc plain-32.bin issuer-serial.der  -aes-256-cbc        -recip recipient-cert.pem "${OAEP[@]}"
enc plain-32.bin two-recipients.der -aes-256-cbc -keyid -recip recipient-cert.pem "${OAEP[@]}" -recip other-cert.pem "${OAEP[@]}"
enc plain-32.bin aes256gcm.der      -aes-256-gcm -keyid -recip recipient-cert.pem "${OAEP[@]}"
"$O" cms -encrypt -binary -in plain-32.bin -aes-256-cbc -keyid -recip other-cert.pem "${OAEP[@]}" -outform DER -out other-recipient.der
rm -f other-cert.pem
sha256sum * 2>/dev/null > SHA256SUMS || shasum -a 256 * > SHA256SUMS

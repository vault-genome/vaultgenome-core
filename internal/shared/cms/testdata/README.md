# CMS vectors made by OpenSSL 3

OpenSSL 3.6.4 (`openssl-version.txt`) — an implementation nobody here
wrote — made every `.der` and `.ber` file here with `make-vectors.sh`,
on 2026-10-23. `SHA256SUMS` lists them.

`recipient-key.pem` is a throwaway RSA-3072 key made for these vectors and
used for nothing else; `recipient-cert.pem` is its self-signed certificate,
with the subject key identifier the profile names the recipient by.
gitleaks' private-key rule matches the PEM block by shape; the file is
allowlisted by path in `.gitleaks.toml` for that reason.

| File | What it is | Expected |
|---|---|---|
| `kms-profile-32.der` | the KMS profile, 32-byte content (a data key), DER | opens to `plain-32.bin` |
| `kms-profile-32-stream.ber` | the same, `-stream`: indefinite lengths, the content in two OCTET STRING chunks | opens to `plain-32.bin` |
| `kms-profile-4096.der` | 4096-byte content (KMS's largest plaintext), DER | opens to `plain-4096.bin` |
| `kms-profile-4096-stream.ber` | the same, indefinite lengths | opens to `plain-4096.bin` |
| `oaep-sha1.der` | RSAES-OAEP without parameters — SHA-1 by default | refused |
| `pkcs1v15.der` | the key wrapped with RSA PKCS #1 v1.5 | refused |
| `aes128cbc.der` | AES-128-CBC content | refused |
| `issuer-serial.der` | the recipient named by issuer and serial number (version 0) | refused |
| `two-recipients.der` | a second recipient | refused |
| `aes256gcm.der` | AuthEnvelopedData (AES-256-GCM), another content type | refused |
| `other-recipient.der` | the profile, wrapped to another key | does not unwrap |

The profile is what AWS KMS answers an attested request with
(CiphertextForRecipient): EnvelopedData version 2, one
KeyTransRecipientInfo version 2 naming its recipient by subject key
identifier, RSAES-OAEP with SHA-256 and MGF1-SHA-256, AES-256-CBC — as the
AWS Nitro Enclaves SDK reads it (`source/cms.c` at cd61b61).

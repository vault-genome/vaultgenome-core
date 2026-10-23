# A genome key released across clouds into a Nitro enclave

ADR 0036, part four, decision 6. `run.sh`, from the operator's machine
under the kit's role (`../iam/`), plays the cross-cloud key release with
a Nitro enclave as the destination:

1. **The source authority** on a GCP AMD SEV-SNP Confidential VM
   (`authority.sh`): `sagvd` attests with the chip through the kernel's
   configfs-tsm, its key files are sealed to the chip (`sagvd seal-keys`),
   a genome is sealed with `acpctl genome seal`. The destination's TLS
   pair, the CA and the bearer token are taken before the sealing, for the
   operator.
2. **The destination** on an m5.xlarge in AWS: an enclave image of one
   static `acp-bootstrap`, its configuration, the authority's public key,
   the TLS certificate and the CA — so PCR0 covers them all — and nothing
   secret. The enclave's key files (the TLS server key, the bearer token)
   are sealed on the operator's machine for that PCR0 (`acp-bootstrap
   seal-keys -pcr0 -root`) under a KMS key whose policy releases to the
   image alone; the parent (`parent/`) hands them to the enclave at start,
   and the enclave opens them through KMS with its own attestation
   document. The parent forwards the authority's TLS from its port 8443 to
   the enclave's vsock port and the enclave's TLS to KMS; it reads none of
   it. The log comes back over vsock, since a production-mode enclave has
   no console.
3. **The release**: the sealed bundle into the enclave over the API; the
   genome key released by `sagvd crosscloud-restore` only after the
   enclave's document verified against the registry's policy — PCR0 as the
   measurement, PCR1 and PCR2 pinned, the AWS root pinned, debug mode
   refused, the nonce the key-binding challenge; the enclave restores the
   genome in its memory; `sagvd crosscloud-confirm` confirms the restore
   from the enclave's NSM-signed receipt, held to the bundle the operator
   sealed.
4. **Refused, each on the record** (`KEY_RELEASE_DENIED`): an image the
   allow-list does not name; PCR2 pinned to another value; the operator
   stop; and the same image in debug mode, started with its key files in
   the clear as an insider could — the authority refuses its document by
   its zero PCR0, whatever it holds.
5. **The audit log** verified by `acpctl audit verify` and by the auditor's
   own verifier (`tools/auditor/verify_audit.py`), to the same count.
6. **CloudTrail**: the two Decrypts the production enclave made for its
   key files, each with the enclave's document as Recipient, and no other.
7. Teardown in both clouds, whatever happened; the key scheduled for
   deletion.

```bash
VG_GCP_PROJECT=<the GCP project> scripts/hardware-test/aws-nitro/crosscloud-e2e/run.sh
```

Needs the AWS CLI with the operator's credentials, `gcloud` logged in to
the project, Go, Python 3 and SSH. The verdict (`verdict.py`), check by
check, is taken on the evidence as recorded and kept with it
(`verdict.txt`). Then `redact.py` takes out what names the account: its
number, the three addresses (the operator's, the parent's, the
authority's), every IAM unique identifier and PCR3; the receipt's
attestation document — which carries PCR3 — is withheld and its SHA-256
kept in its place. The run removes the evidence if any of that, or the
run's AWS secret key or session token, is still in it.

# The sealer on a Nitro enclave, against KMS itself

ADR 0036, part four, stage one. `run.sh`, from the operator's machine under
the kit's role (`../iam/`), proves the Nitro enclave's sealer on hardware:

1. Two KMS keys for the run. The policy of one admits the run's image; the
   other's admits another. Both deny `kms:Decrypt` to every principal when
   no attestation document comes with it.
2. An `m5.xlarge` with enclaves on, its role without permissions of its
   own, IMDSv2 only, reachable by SSH from the operator's address alone.
3. The enclave image: one static program (`enclave/`) and its
   configuration — the keys and the parent's vsock ports — so PCR0 covers
   both. The key policy is then pinned to that PCR0.
4. Secrets sealed on the operator's machine with the shipping sealer
   (`seal/`): 64 random bytes for the image's PCR0; the same for another
   PCR0; the same sealed under another name and handed over as this one;
   the same under the key whose policy admits another image.
5. The enclave in production mode: it attests itself with the shipping
   producer, opens each file with the shipping sealer — KMS `Decrypt` with
   its own attestation document as Recipient, KMS's CMS opened inside —
   and reports what opened (as a SHA-256) and what was refused, by name.
   The parent (`parent/`, on `internal/shared/vsock`) forwards its TLS to
   KMS and its HTTP to the instance metadata service, and reads neither.
6. The parent's own role, and the kit's, ask KMS for the data key without
   an enclave: both refused.
7. The same image in debug mode: its document says PCR0 zero; the shipping
   sealer is not built on it, and KMS refuses a debug-mode document sealed
   for the production PCR0.
8. Teardown, whatever happened: the instance, the security group, the key
   pair; the keys scheduled for deletion (seven days).
9. CloudTrail: every `Decrypt` on the run's keys, as AWS recorded it — for
   the one granted, the enclave's module and its image digest.

```bash
scripts/hardware-test/aws-nitro/sealer-e2e/run.sh
```

Needs the AWS CLI with the operator's credentials, Go, Python 3 and SSH.
The evidence goes to `evidence/<UTC time>/` with the account number, the
operator's and the parent's addresses and any access key taken out; the
run stops before keeping evidence a credential reached, and ends with a
verdict, check by check.

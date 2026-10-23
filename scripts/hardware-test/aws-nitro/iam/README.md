# The Nitro kit's two roles

`vaultgenome-nitro-kit-iam.yaml` is a CloudFormation template an account
administrator creates once, in the Region the kit runs in (CloudFormation,
Create stack, With new resources, Upload a template file, stack name
`vaultgenome-nitro-kit`, acknowledge the IAM resources). It makes:

- **`vaultgenome-nitro-kit`** — the role the kit assumes for each run, for
  at most two hours, from the operator's IAM user (`OperatorUserName`; the
  trust names the user, so the user needs no policy of its own). It may act
  in one Region only; launch only `m5.xlarge` or `m5.2xlarge`; tag only what
  it creates and stop, terminate or delete only what carries
  `vaultgenome-kit=nitro`; hand the parent its role and no other; create
  KMS keys tagged as the kit's, write their policies, ask them for data
  keys under the sealer's encryption context and schedule their deletion;
  read CloudTrail. It has no `kms:Decrypt`.
- **`vaultgenome-nitro-parent`** and its instance profile — the enclave's
  parent instance. No permissions of its own: each run's key policy grants
  it `kms:Decrypt` only when the request carries the attestation document
  of the run's enclave image (`kms:RecipientAttestation:ImageSha384`) and
  the encryption context names that image; every principal is denied
  `kms:Decrypt` without an attestation document.

Deleting the stack removes all three.

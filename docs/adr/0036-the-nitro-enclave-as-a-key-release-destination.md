# ADR 0036 — The Nitro enclave as a key-release destination: the NSM spoken from its interface, the enclave reached over vsock, its secrets released only to its measurement, the contour proven across clouds

- **Status:** Accepted (2026-10-23) — parts one to four implemented: the producer (the NSM spoken from the kernel's and AWS's interface, a self-check at start), `acp-bootstrap` over vsock with the bundle into the enclave over the API, the sealer (Signature Version 4, KMS's CMS, the envelope), the sealer in an enclave against KMS itself, and the key release across clouds into a production-mode enclave with the family's refusal lifted (C51, C52); part five (the Nitro corpus against two outside readings) follows
- **Date:** 2026-10-23
- **Deciders:** Serhii Nikolaichuk, Rodion Sorokin
- **Extends:** ADR 0035 (the Nitro verifier from the specification), ADR 0009 and 0029 (the cross-cloud key release), ADR 0011 (the restore receipt), ADR 0033 (the attack record in the policy), ADR 0034 (the corpus)

## Context

The Nitro verifier is written from AWS's specification and proven offline
on the hypervisor's own documents (ADR 0035, C49); the producer and the
sealer are still stubs, and the verifier registry and `acp-bootstrap`
refuse the `aws-nitro` family until an enclave has attested to this code
live and taken a release end to end. SEV-SNP and TDX went the whole way
— a genome key released across clouds to the chip's attested key, the
restore confirmed from a receipt the chip signed, the refusals on the
record. Nitro has to go the same way, and it is not the same place:

- **An enclave has no network and no persistent storage; vsock is its only
  channel**, the parent's CID is always 3 (AWS, *Nitro Enclaves concepts*,
  library `ca1b50d8d809…`). The enclave's init loads AWS's `nsm.ko` and brings up
  no network interface — not even loopback (`init.c` of
  aws-nitro-enclaves-sdk-bootstrap, `72343e84be70…`; the kernel nitro-cli ships,
  4.14.256, has `CONFIG_VSOCKETS` and `CONFIG_HW_RANDOM_VIRTIO`,
  `9378dea490ed…`). A daemon in an enclave listens on vsock or nowhere.
- **The NSM is a character device with one ioctl.** `NSM_IOCTL_RAW` =
  `_IOWR(0x0A, 0, struct nsm_raw)` = `0xC0200A00`: two iovecs, the request
  at most 4096 bytes, the response at most 12288 (Linux `uapi/linux/nsm.h`,
  `a4bd3e142752…`; AWS's NSM API driver, the same code, `3c38cc5dd0b9…`). The request
  and the response are CBOR, the enums of AWS's NSM API serialised
  externally tagged: `{"Attestation": {"user_data", "nonce", "public_key"}}`
  → `{"Attestation": {"document"}}` or `{"Error": "<code>"}` (`9492676eb25e…`);
  each optional field at most 1024 bytes (the attestation document's
  specification, `52828d11fb41…`).
- **KMS releases to an enclave only through its attestation document**:
  `Decrypt` with a `Recipient` — the document, which carries the enclave's
  public key, and `RSAES_OAEP_SHA_256`, the only key-encryption algorithm —
  returns `CiphertextForRecipient` instead of plaintext (`5ed19c1a739c…`,
  `4a45ca57400f…`); a key policy can require the document's image hash and PCRs
  (`61c61ec64a4d…`). The ciphertext is CMS EnvelopedData whose content is
  **AES-256-CBC** — encryption without authentication (the SDK's own parser,
  `4a1eb8e896d2…`).
- **The enclave's clock drifts by seconds from its parent's**
  (aws-nitro-enclaves-cli issue 500, in the library); the document's
  timestamp is the hypervisor's, not the enclave's.
- **The document tells less than an SEV-SNP report.** PCR0 (the image),
  PCR1 (the kernel and boot ramfs), PCR2 (the application), PCR3 (the
  parent's IAM role), PCR4 (the parent instance), PCR8 (the image's signing
  certificate); no firmware or TCB version of the Nitro hypervisor at all.
  The hypervisor is AWS's, and nothing in the document lets a verifier hold
  it to a floor.

## Decision

1. **The producer speaks the NSM from its interface**, in the tree, with the
   standard library: `/dev/nsm`, `NSM_IOCTL_RAW` through the `syscall`
   package, the request encoded by the codec of ADR 0035 exactly as AWS's
   NSM API encodes it (byte for byte, held by a test), the response decoded
   by the same strict decoder, the `Error` variant named in the refusal, the
   limits of the interface enforced before the call. The verifier's
   challenge goes into `nonce`, as the verifier expects. **At start the
   producer attests itself**: a document over a random nonce, verified
   whole with the shipping verifier — the pinned AWS root, the chain, the
   signature, the nonce, not debug-mode — and PCR0 taken from it; a device
   that answers wrongly stops the daemon before it serves. No
   `DescribePCR`: its response carries a boolean the document never does,
   and the decoder stays the document's.
2. **`acp-bootstrap` is reached over vsock**: an `AF_VSOCK` listener written
   with the `syscall` package (`struct sockaddr_vm`, Linux
   `uapi/linux/vm_sockets.h`, `e8153fea6dbd…`); TLS terminates inside the enclave;
   the parent forwards bytes between a TCP port and the enclave's vsock
   port and sees ciphertext. Nothing in the enclave dials out except the
   vsock ports the image names. (Part two.)
3. **The bundle travels into the enclave over the same authenticated API**
   — sealed, so ciphertext — held in the enclave's memory; the key comes
   only from the release, and the receipt names the bundle's digest, which
   the source holds to its own (ADR 0011): a bundle swapped on the way is
   caught. Nothing genome-specific is built into the image, so PCR0 does
   not change per genome. (Part two.)
4. **What is not secret is in the image; what is secret is released by KMS
   only to the image.** The source authority's key, the profile, the suites
   and the vsock ports are in the image, so PCR0 covers them. The TLS
   server key and the bearer token are envelope-encrypted: AES-256-GCM
   under a data key that KMS releases only to a document whose image hash
   is the enclave's (`kms:RecipientAttestation:ImageSha384`, PCR8 when the
   image is signed). The CMS layer's CBC never carries anything used
   unauthenticated — what it carries is a key, and what that key opens is
   authenticated. The enclave calls KMS itself, TLS end to end through the
   parent's vsock proxy, the request signed with Signature Version 4
   written from the specification, with the parent role's credentials —
   which the parent holds anyway; the key policy is what protects. (Part
   three.)
5. **The source admits an enclave by a policy, and the record says what it
   read**: a set of PCR0 (required), PCR1, PCR2, PCR3 and PCR8 pins on
   request, debug-mode refused, the AWS root pinned, the document's
   timestamp within the skew, the nonce equal to the key-binding challenge;
   `AttestationDetail.nitro` with the PCRs, the module id and the
   timestamp on every admission and release record; the policy on
   `identity`. PCR0 is required because a debug-mode enclave keeps its
   parent's PCR3 and PCR4 (C51): pins on the parent alone would admit
   it. What cannot be held — the hypervisor's version — is written
   down as the platform's, not ours. The family's refusal was lifted in
   the pull request that carried decision 6's run, not before. (Parts
   three and four.)
6. **The proof is across clouds**: a genome key released by an authority on
   a GCP SEV-SNP Confidential VM to `acp-bootstrap` in a production-mode
   Nitro enclave on an m5.xlarge, over the Internet; the genome restored
   inside the enclave and confirmed from its NSM-signed receipt; an enclave
   not on the allow-list, a debug-mode enclave and an operator stop
   refused; the audit log verified, also by the auditor's own tool (ADR
   0034). (Part four.)
7. **The Nitro documents become a corpus** like ADR 0034's — the published
   capture of May and the kit's new ones — held against two readings
   nobody here wrote, hf/nitrite (Go, MIT) and AWS's aws-nitro-enclaves-cose
   (Rust, Apache-2.0), through the harness. (Part five.)

## Alternatives considered

- **AWS's SDKs** (the Go SDK for KMS, the NSM API through cgo, the Nitro
  Enclaves SDK in C). The interfaces are small and specified; the product's
  trust base stays the standard library (`ci-security-policy` §3.1). Not
  taken.
- **`DescribePCR` for the measurement.** A boolean in the response, a
  branch the document's decoder would have to grow; and a self-attested
  document checks more. Not taken.
- **The bundle or the secrets built into the image.** PCR0 per genome; a
  secret readable by anyone holding the image file. Not taken.
- **The parent calling KMS for the enclave.** The CMS content is CBC; a
  parent in the middle could tamper with it. The enclave calls KMS itself,
  and what it unwraps is authenticated anyway. Not taken.
- **NitroTPM (EC2 instance attestation) instead of enclaves.** A different
  isolation — the whole instance, not a carved-out VM; a family of its
  own, later.

## Consequences

- A daemon in an enclave serves only over vsock; the kits and the operator
  guide carry the parent's forwarder and the KMS proxy.
- The source's policy gains a Nitro section, and its records a Nitro
  detail, the way ADR 0033 added SEV-SNP's.
- The enclave has no clock it can trust beyond seconds; nothing in the
  enclave relies on more (TLS certificate validity is days; the document's
  freshness is checked at the source against the hypervisor's timestamp).

## Implementation notes

- **Part one (code):** `internal/shared/tee/aws_nitro_nsm.go` (the request
  encoder, the response decoder, the limits), `aws_nitro_nsm_linux.go` (the
  ioctl), the producer's self-attestation at start, the fakes and tests on
  genuine CBOR — the encoding held byte for byte to AWS's, every NSM error
  code, every limit.
- **Part two (code):** `internal/shared/vsock` — `AF_VSOCK` with the
  `syscall` package: socket, bind, accept4 and connect made raw on a
  16-byte `struct sockaddr_vm` (the syscall package's `Accept4` closes a
  descriptor whose peer family it does not know, and it does not know
  vsock), the listener and the connections as `*os.File` on non-blocking
  descriptors so the runtime's poller drives them, deadlines included,
  and `Close` unblocks `Accept`; Linux on amd64 and arm64, a refusal
  elsewhere. `acp-bootstrap`: `http.listen_vsock_port`, held to the rules
  of a non-loopback address; `POST /v1/genome/bundles` with
  `genome.max_bundle_bytes`, through `bundle.Store` in the package that
  owns bundle files (the doctrine's no-raw-export check holds writes
  there) — a staged file under a name the scan
  ignores, the v3 header checked, `<sha256>.genome` by a rename, one
  bundle per key. Tested on Linux over the kernel's vsock loopback
  (`vsock_loopback`): bytes both ways, deadlines, `Close` unblocking
  `Accept` with `net.ErrClosed`, TLS 1.3, and the daemon's own server
  answering over vsock — five runs out of five on Ubuntu 24.04, kernel
  7.0.0-1014-gcp (2026-10-23); the gate loads the module so CI runs them.
  That run found two defects before any enclave did: a non-blocking
  connect that answered "wait" on the first call lost the poller's
  readiness, which preparing the wait clears, so `Dial` now asks SO_ERROR
  and getpeername(2) on every wake, as Go's own `net` does; and the raw
  read behind `Accept` reports a closed listener as the poller's "use of
  closed file", so `Close` sets a flag `Accept` answers from.
- **Part three (code):** the KMS sealer, each part with the standard
  library and each held to something nobody here wrote.
  `internal/shared/awssigv4` — Signature Version 4 from the IAM User
  Guide (header form; the presigned form is not needed), held to AWS's
  own suite: all 38 cases of aws-c-auth at `84a26ea` byte for byte, the
  vectors in testdata under their Apache-2.0 LICENSE and NOTICE.
  `internal/shared/cms` — BER from X.690 (definite and indefinite
  lengths, constructed strings) and EnvelopedData in exactly the profile
  the SDK reads (`cms.c` at `cd61b61`): version 2, one recipient by
  subject key identifier, RSAES-OAEP with SHA-256 and MGF1-SHA-256 and
  no label — absent parameters mean SHA-1 and are refused — AES-256-CBC
  with a 16-byte IV; held to vectors OpenSSL 3.6.4 made, mutated at every
  level, cut at every length, fuzzed. `internal/shared/awskms` —
  GenerateDataKey, Decrypt and GenerateRandom from the API Reference,
  TLS 1.3 to the endpoint verified against Amazon Trust Services' four
  roots and no other (a parent cannot stand in for KMS with a
  certificate a wider store would take), no proxy from the environment,
  every answer held to its form (for a Recipient a CiphertextForRecipient
  and no plaintext; the key named the key asked for); credentials handed
  in by the caller — the operator's, which a command's `main` reads at
  startup (the library reads no environment) — or the instance metadata
  service's, version 2 (through the parent, from an enclave — they buy
  the parent nothing, since the policy releases only to the enclave's
  document).
  Run against KMS itself (`scripts/hardware-test/aws-nitro/kms-live`,
  us-east-2, 2026-10-23): a correct signature accepted, a wrong secret,
  a date twenty minutes behind ("Signature expired" — KMS allows five
  minutes, so the enclave's drift of seconds is nothing) and an unknown
  key refused by the service, an empty root pool refused at the
  handshake (C50). The sealer
  (`internal/shared/tee/aws_nitro_sealer.go`, kind `aws-kms-attested`):
  Seal asks GenerateDataKey for an AES-256 key under the encryption
  context `{vault-genome:sealed-secret: v1, vault-genome:pcr0: <the
  image>, vault-genome:aad-sha256: <the secret>}` and seals with
  AES-256-GCM, the key's ARN and the AAD in the GCM AAD; Unseal makes a
  fresh RSA-3072 key, takes an NSM document carrying it, asks Decrypt
  with the key's ARN, the context of its own PCR0 and the document as
  Recipient, opens the CMS and then the GCM. A file sealed for another
  image or as another secret is refused by KMS (the context differs),
  an image the policy does not admit is refused by KMS
  (AccessDeniedException), each named. Sealing needs no enclave and
  opening is only in one; `acpctl recover` refuses a Nitro vault by
  name. The key policy the operator guide will carry: GenerateDataKey
  for the operator's role only; Decrypt for the instance's role only
  under `kms:RecipientAttestation:ImageSha384`; Decrypt denied to every
  principal when the request carries no attestation document
  (`Null` on that key). What the envelope does not stop: a parent can
  hand the enclave an older sealed file of the same secret for the same
  image — a bearer token from before a rotation. What the token and the
  TLS key guard is the channel into the enclave, and what crosses it is
  checked on its own (the bundle by its digest at the source, ADR 0011;
  the receipt by the NSM's signature); an operator who must make an old
  file useless seals under a new KMS key, which is a new image. A debug
  enclave cannot even ask: its PCR0 is zero, and the sealer is not built
  on a zero measurement. Wiring the sealer into `acp-bootstrap` — its
  `tee.aws_kms`, `seal-keys` for an image's PCR0, the sealed files
  brought into the enclave by its parent — goes with part four, where
  the family's refusal is lifted on hardware.
- **Part four, stage one (hardware):** the sealer in a production-mode
  enclave against KMS itself (`scripts/hardware-test/aws-nitro/sealer-e2e`,
  C51). The kit works under its own role
  (`scripts/hardware-test/aws-nitro/iam/`, a CloudFormation stack the
  operator creates: the run's instance, keys and key policies, CloudTrail
  read, and no `kms:Decrypt`), and makes two keys — the
  policy of one admits the image, the other's another image, and both
  deny Decrypt to every principal when no attestation document comes
  with it — and an m5.xlarge whose role has no permissions of its own.
  The image is one static probe program and its configuration, so PCR0
  covers the keys and the parent's ports; the program attests itself
  with the shipping producer and opens each sealed file through
  `tee.SealerFor` and `tee.OpenSecretWith`, as `acp-bootstrap` will.
  The production enclave opens the secret sealed to its image; KMS
  refuses another image's file and another secret's
  (InvalidCiphertextException), and the key that admits another image
  refuses this one (AccessDenied); in debug mode the sealer is not built
  on the zero PCR0, and KMS refuses the debug document a key sealed for
  the production image; the parent's role and the kit's, without an
  enclave, meet the explicit deny. CloudTrail records the seven calls:
  the granted one's Recipient is the enclave's own document — module
  id, PCR0 as the image digest, PCR1 to PCR4 and PCR8 as the enclave
  reported them — and its credentials came by IMDSv2. What the hardware
  showed:
  - the enclave's init sends its boot heartbeat to the parent on vsock
    port 9000, where nitro-cli listens; a parent helper bound there
    makes the enclave fail to boot (E36);
  - init mounts `/dev`, `/proc`, `/sys`, `/run` and `/tmp` in the
    image's root, so an image built from scratch carries those
    directories;
  - a parent that closed right after writing left the enclave's first
    read with ENOTCONN on the 4.14 kernel, so the reader closes first
    and the writer waits for it;
  - CloudTrail writes the attestation's measurements in base64, and a
    Decrypt refused at the policy as errorCode AccessDenied with no
    request parameters and no resources — the key named only in the
    error message;
  - **in debug mode PCR0, PCR1 and PCR2 are zero, but PCR3 and PCR4
    still measure the parent**, though AWS's guide says a debug-mode
    document's PCRs are all zero (*Cryptographic attestation*, SHA-256
    `103f2fd1…` as read on 2026-10-23): a key policy that pins only the
    parent admits a debug-mode enclave on it, so the image has to be
    pinned, as here and in decision 5;
  - PCR3 is SHA-384 over 48 zero bytes and the parent role's ARN, as
    the guide computes it (PCR4 the same over the instance id), so it
    names the account at a search of twelve digits; the evidence
    withholds it, and every IAM unique identifier — a role's encodes the
    account number, as an access key's does.
- **Part four (the release across clouds):** the source's policy and
  record — `AWSNitroVerifierConfig.PCRPins` (PCR1, PCR2, PCR3, PCR4 and
  PCR8 by index, each a 48-byte value; a pin on PCR0 itself, on a PCR a
  document does not define, of another length or of zeros refused at
  construction), `VerifyDetailed` giving the record the module, the
  hypervisor's timestamp, every PCR the document defines, the pins and
  the user data's digest (`AttestationDetail.Nitro`); in the registry,
  `expected_measurement_hex` is PCR0 (48 bytes, or refused) and `nitro`
  carries the pins and the clock skew. `acp-bootstrap` in the enclave:
  `tee.provider: aws-nitro` runs the NSM producer; the API on
  `http.listen_vsock_port` and no health listener; the key files from
  the parent on `tee.secret_files_vsock_port` — exactly the paths the
  config names, all or none, in the enclave's memory — opened through
  KMS (`tee.aws_kms`: the key, the parent's ports to KMS and the instance
  metadata service); the log to the parent on `log.vsock_port`; the
  parent's ports distinct and never 9000; the listen addresses' defaults
  yield to an enclave's file. `acp-bootstrap seal-keys -pcr0 -root`
  seals the files outside the enclave, for the image. The kit
  (`scripts/hardware-test/aws-nitro/crosscloud-e2e`): the authority on a
  GCP SEV-SNP Confidential VM, its key files sealed to the chip; the
  enclave on an m5.xlarge; the parent's four forwarders and nothing read;
  the release, the restore in the enclave's memory, the receipt confirmed,
  four refusals, the audit log verified twice, CloudTrail's two Decrypts.
  Run `20261023T182103Z` on `b51d54bc`: 26 checks of 26 (C52). What the run showed:
  - the first run stopped at `seal-keys` — the image's configuration named
    a vsock port and no `listen_address`, and the default address made
    the two look set together; the defaults are a networked host's and
    now yield to an enclave's file;
  - `CROSS_CLOUD_ATTESTATION_VERIFIED` is written when the document
    verifies, before the policy decides: the release has one, and so do
    the allow-list's and the stop's refusals; the pin's and the debug
    document's refusals come before one — the verdict counts three;
  - the receipt carries the enclave's document whole, and the document
    carries PCR3, which names the account: the evidence withholds the
    document and keeps its SHA-256;
  - the production enclave opened its two key files through KMS and
    served within ten seconds of its start; the debug-mode enclave,
    started with the same files in the clear, served too, and the
    authority refused its document by its zero PCR0.
- **Part five:** the Nitro corpus and its two outside readings.

## References

The library (`_LIBRARY/sources/MANIFEST.tsv`, read 2026-10-23, each with
its SHA-256): AWS's NSM API at `4bf743e` (`src/api/mod.rs`,
`src/driver/mod.rs`, `docs/attestation_process.md`); Linux v6.12
`drivers/misc/nsm.c`, `include/uapi/linux/nsm.h`,
`include/uapi/linux/vm_sockets.h`; vsock(7); the enclave init of
aws-nitro-enclaves-sdk-bootstrap at `f718dea` and the enclave kernel's
configuration of aws-nitro-enclaves-cli at `1c496ed`; the AWS Nitro
Enclaves SDK in C at `cd61b61` (`source/cms.c`, `source/kms.c`); the KMS
API reference (`Decrypt`, `RecipientInfo`), the KMS developer guide
(attestation condition keys, *How AWS Nitro Enclaves uses AWS KMS*), the
Nitro Enclaves user guide (concepts, attestation, root verification);
hf/nitrite at `c2d5d3c`; aws-nitro-enclaves-cose at `d940631`. For part
three: the IAM User Guide's Signature Version 4 pages and aws-c-auth at
`84a26ea` (the test suite); RFC 5652, RFC 3560, RFC 4055, RFC 3565 and
ITU-T X.690 (02/2021); the KMS API Reference (GenerateDataKey,
GenerateRandom, common parameters and errors) and developer guide
(attested calls, the Nitro Enclaves condition keys, CloudTrail of attested
requests); the EC2 User Guide on the instance metadata service and role
credentials; Amazon Trust Services' root certificates and repository page,
and the KMS endpoints' TLS chains as observed on 2026-10-23. For part
four: the Nitro Enclaves user guide's *Cryptographic attestation*
(`set-up-attestation`, PCR3 and PCR4 and how to compute them, debug
mode), read again on 2026-10-23; the kit's parent and authority scripts
name every port and path the decision rests on.

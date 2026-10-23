# ADR 0036 — The Nitro enclave as a key-release destination: the NSM spoken from its interface, the enclave reached over vsock, its secrets released only to its measurement, the contour proven across clouds

- **Status:** Proposed (2026-10-23) — the design; part one (the producer: the NSM spoken from the kernel's and AWS's interface, a self-check at start) and part two (`acp-bootstrap` over vsock, the bundle into the enclave over the API) with it; parts three to five follow after
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
   `identity`. What cannot be held — the hypervisor's version — is written
   down as the platform's, not ours. The family's refusal is lifted in the
   pull request that carries the hardware run, never before. (Parts three
   and four.)
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
- **Part three (code):** the KMS sealer — SigV4, `Decrypt` with a recipient,
  the CMS EnvelopedData with RSA-OAEP-SHA-256 and AES-256-CBC, the
  envelope AES-256-GCM.
- **Part four (hardware):** the policy and the record at the source; the
  kit across clouds; the family's refusal lifted; claims.
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
hf/nitrite at `c2d5d3c`; aws-nitro-enclaves-cose at `d940631`.

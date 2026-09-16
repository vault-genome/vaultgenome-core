# NVIDIA GPU attestation test material

Public documents, fetched on 2026-09-16, for the verifier's own evaluation
of an H100's attestation report (`nvidia_gpu_report.go`, `nvidia_rim.go`):

- The two NVIDIA roots — the NVIDIA Device Identity CA (self-signed,
  SHA-256 fingerprint `102bf659…167b48`) and the NVIDIA CoRIM signing Root
  CA (fingerprint `12977b51…1df5d1`), both as shipped in NVIDIA's
  open-source verifier (github.com/NVIDIA/nvtrust,
  `guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/certs/`) —
  are pinned in the binary (`../../nvidia_roots.go`); the tests use them
  from there (the repository ignores `*.pem`, on purpose).
- `rim-NV_GPU_DRIVER_GH100_595.71.05.json` and
  `rim-NV_GPU_VBIOS_1010_0210_886_96009F0004.json` — the driver and VBIOS
  reference integrity manifests of the H100 captured in
  `scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z/`, as the
  RIM service returned them (`https://rim.attestation.nvidia.com/v1/rim/<id>`:
  `id`, `rim` — the signed SWID tag, base64 — and the service's `sha256`).

The attestation report and certificate chain the tests evaluate are the
captured `gpu0-attestation-report.bin` and `gpu0-cert-chain.pem` of that
evidence directory, taken for the nonce in its `nonces.txt`.

## `ocsp/` — NVIDIA's OCSP responses for the captured chain

Fetched on 2026-09-16 at 23:21:39Z from `http://ocsp.ndis.nvidia.com`
(the AIA URL the intermediates carry), one per certificate of the captured
H100's chain that the responder serves, each asked by its issuer with a
SHA-256 CertID and a nonce (`openssl ocsp -sha256 -issuer … -cert … -url
… -respout …`):

- `gh100-a01-gsp-brom.der` — the "GH100 A01 GSP BROM" certificate, by the
  Provisioner ICA 1: `good`, signed by "NVIDIA OCSP Responder L3 GH100
  ICA1 Identity" (delegated responder, its certificate embedded);
- `gh100-provisioner-ica1.der` — "NVIDIA GH100 Provisioner ICA 1", by
  "NVIDIA GH100 Identity": `good`, signed by "NVIDIA OCSP Responder L2
  GH100 Identity";
- `gh100-identity.der` — "NVIDIA GH100 Identity", by the NVIDIA Device
  Identity CA: `good`, signed by "NVIDIA OCSP Responder L1-A 02".

Each says `thisUpdate 2026-09-16T23:21:39Z`, `nextUpdate
2026-09-17T23:21:39Z` (a day); ECDSA-SHA384. The per-GPU leaf ("GH100 A01
GSP FMC LF", by the BROM certificate) is not served: the responder
answers `unauthorized` for it, in every request form tried — its status
is the BROM's, the ICA's and the Identity CA's. The tests pin the clock
inside the responses' day; they are evidence of the responder's shape,
not a live status.


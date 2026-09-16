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

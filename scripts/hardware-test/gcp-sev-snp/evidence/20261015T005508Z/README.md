# GCP SEV-SNP — the run of 2026-10-15 (the manifest names what was sealed)

The same kit and VM shape as the run of 2026-10-14 (`../20261014T231645Z/`):
one `n2d-standard-4` Confidential VM (Milan) in `us-central1-c` after
`us-central1-a` and `-b` refused for capacity, image family
`ubuntu-2404-lts-amd64`, driven end to end by `examples/full-test-run.sh`
on the tree of commit `7ec57ae` (`acpctl` sha256
`5cf55e9f889a25a22a05fbf9f04dd9fb332cdb99f91791dc75317ff8d3058d4a`, Go tree
unchanged since `85f6a11`). Started 00:46Z, finished 00:56:17Z, VM destroyed
by the runner. `full-test-run.log` is the runner's output.

What changed in the run (#83): Demo 1 ran **before** the chain step and
wrote `demo1-inspect.json` — `acpctl genome inspect --json` of the bundle it
sealed. The chain step's workload manifest
(`attestation-validation/<vm>/01-vaultgenome-payload-manifest.json`) names
that measurement:

| field | value | from |
|---|---|---|
| `payload_sha256` | `c42f7c25e88d…e1f074` | the sealed components, as acpctl measured them |
| `payload_size_bytes` | 2 019 402 752 | `payload_bytes` |
| `bundle_sha256` | `35920695…` | the bundle file |
| `bundle_size_bytes` | 2 019 436 684 | the bundle file |
| `sealed_at` | 2026-10-15T00:50:29Z | the bundle header |
| `payload_measured_by` | the method, named | — |

REPORT_DATA = SHA-512(this manifest) went into the hardware report
(`04-attestation-report.bin`, requested 00:54Z), and snpguest verified the
binding after verifying the chain (ARK → ASK → VCEK from AMD KDS) and the
report's signature: `11-policy-validation-summary.txt` reads ALL POLICY
CHECKS PASSED with the line "REPORT_DATA = SHA-512(manifest) — the manifest
names what Demo 1 sealed, as measured". The run of 2026-10-14 bound a
manifest whose payload digest was a constant the kit carried; this one
binds the digest of the bundle the run produced.

The rest is as on 2026-10-14: the report from `/dev/sev-guest`
(`snp-attestation-report.bin`, kernel log in `kernel-sev.txt`); Demo 1 —
seal, open, verify, one flipped byte refused with exit 4 (`demo1-*.txt`);
Demo 2 — six generations, lineage, rewind (`demo2-*.txt`); inference —
the original and the restored model's answers byte-identical
(`inference-*.txt`). Text files have the VM user's home directory replaced
by `~`; the report, the certificates and the binary files are byte for byte
what the VM produced.

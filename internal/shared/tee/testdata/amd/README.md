# AMD KDS certificate chains (ASK then ARK), one per product line

Fetched on 2026-10-15 from AMD's Key Distribution Service over TLS:

| File | URL | ARK subject | ARK SHA-256 fingerprint |
| - | - | - | - |
| `kds-Milan-cert_chain.pem` | `https://kdsintf.amd.com/vcek/v1/Milan/cert_chain` | `CN=ARK-Milan` | `69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd` |
| `kds-Genoa-cert_chain.pem` | `https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain` | `CN=ARK-Genoa` | `4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1` |
| `kds-Turin-cert_chain.pem` | `https://kdsintf.amd.com/vcek/v1/Turin/cert_chain` | `CN=ARK-Turin` | `1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a` |

The same three fingerprints were read, independently, from the copies
already in this tree (`scripts/hardware-test/gcp-sev-snp/keybind-evidence/20260913T222343Z/kds-vcek-cert_chain.pem`,
Milan, KDS 2026-09-13; `scripts/hardware-test/azure-sev-snp/evidence/20261015T042715Z/thim-cert-chain.pem`,
Genoa, served by Azure THIM) and from the roots embedded in Google's
`go-sev-guest` (`verify/trust/ask_ark_{milan,genoa,turin_vcek}.pem`,
v0.15.1). These files are test fixtures; the roots the product pins are
the same bytes in `internal/shared/tee/amd_roots.go`.

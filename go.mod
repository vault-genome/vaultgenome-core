module github.com/vault-genome/vaultgenome-core

go 1.27.4

// Dependency additions require:
//   1. A justification file at docs/dependencies/<name>.md.
//   2. An entry in scripts/dep_allowlist.txt (docs/doctrine/ci-security-policy.md §3.1).
//   3. PR review acknowledging both of the above.
//
// Current approved direct dependencies:
//   - github.com/beevik/etree             — XML document model under goxmldsig (docs/dependencies/etree.md)
//   - github.com/russellhaering/goxmldsig — XML signatures of NVIDIA's RIMs (docs/dependencies/goxmldsig.md)
//   - github.com/stretchr/testify         — test assertions (docs/dependencies/testify.md)
//   - go.etcd.io/bbolt                    — audit log and job store (docs/dependencies/bbolt.md)
//   - golang.org/x/crypto                 — OCSP and ASN.1 parsing (docs/dependencies/x-crypto.md)

require (
	github.com/beevik/etree v1.8.1
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/stretchr/testify v1.12.1
	go.etcd.io/bbolt v1.5.0
	golang.org/x/crypto v0.58.0
)

require (
	github.com/jonboulle/clockwork v0.5.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

module github.com/ai-continuity-platform/core

go 1.26.0

// Dependency additions require:
//   1. A justification file at docs/dependencies/<name>.md.
//   2. Inclusion in the allowlist at 00_CI_Security_Policy.md §5.
//   3. PR review acknowledging both of the above.
//
// Current approved direct dependencies:
//   - github.com/stretchr/testify   — test assertions (docs/dependencies/testify.md)
//   - go.etcd.io/bbolt              — append-only audit store (docs/dependencies/bbolt.md)

require (
	github.com/beevik/etree v1.7.0
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/stretchr/testify v1.11.1
	go.etcd.io/bbolt v1.3.10
	golang.org/x/crypto v0.57.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

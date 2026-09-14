module github.com/ai-continuity-platform/core

go 1.25.0

// Dependency additions require:
//   1. A justification file at docs/dependencies/<name>.md.
//   2. Inclusion in the allowlist at 00_CI_Security_Policy.md §5.
//   3. PR review acknowledging both of the above.
//
// Current approved direct dependencies:
//   - github.com/stretchr/testify   — test assertions (docs/dependencies/testify.md)
//   - go.etcd.io/bbolt              — append-only audit store (docs/dependencies/bbolt.md)

require (
	github.com/stretchr/testify v1.9.0
	go.etcd.io/bbolt v1.3.10
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

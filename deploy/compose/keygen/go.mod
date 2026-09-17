// Standalone module for the demo keygen tool. Kept deliberately
// independent of the /core module so that the demo provisioning
// surface cannot accidentally depend on production packages (and so
// that changes to /core/go.sum never force a re-hash of demo secrets).
//
// This module is stdlib-only.
module github.com/vault-genome/vaultgenome-core/deploy/compose/keygen

go 1.22

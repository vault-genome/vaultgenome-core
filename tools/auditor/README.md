# The auditor's own verifier of the audit log (ADR 0034, part three)

`verify_audit.py` replays a daemon's audit log with nothing of the product
in it: the standard library of Python only. It reads the bbolt file as
pages, re-encodes every event's canonical JSON as the daemons encode it,
recomputes SHA-256, follows the links from the genesis (or from where a
continued segment says it starts), and checks every signature under the
audit public key `sagvd identity` printed — Ed25519 (RFC 8032) and ECDSA
P-384 (SEC 1), written out in the file so that what is checked can be
read. ML-DSA-87 is not implemented here; a log under it is reported as
not verified by this tool, not as broken.

```bash
python3 -I tools/auditor/verify_audit.py --audit returnpath-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-demo
python3 -I tools/auditor/verify_audit.py --audit xcc-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-demo --json
```

`pip install vaultgenome` installs this same file as the command
`vaultgenome-audit` (the package `vaultgenome.auditor`; no dependencies),
for an auditor who would rather not clone the repository; the wheel is a
release asset, signed like the binaries, and `genome-worker` CI holds the
installed command to the file in the tree on a recorded log.

Exit 0 when every event links and verifies, with the count and the tip;
1 otherwise, naming the first event that does not. Compare the tip with
the one recorded elsewhere (the kits' `audit-verify.json`, the
crosscloud-restore report): a tail cut off the log is invisible to any
replay.

`internal/audit/chain/auditor_differential_test.go` (build tag
`differential`; `make differential`) calls this tool and `acpctl audit
verify` on the same files — every genuine log on record, a log under each
suite, and mutants — and requires the same verdicts, counts and tips. The
runs on record are in `test/corpus/audit/results/`.

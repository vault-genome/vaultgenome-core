# The audit logs on record, for the auditor's verifier (ADR 0034, part three)

The genuine audit logs this tree holds are the authority logs the
hardware kits recorded, each kept beside its key and the product's
verdict of the day: those of the region-loss drills,
`scripts/hardware-test/failover-region-loss/evidence/*/authority/`
(`xcc-audit.db`, `audit.pem`, `audit-verify.json`), and those of the
closed-turn kit, `scripts/hardware-test/closed-turn/evidence/` — its run
and, under `negative/`, its run of refusals (`xcc-audit.db`,
`audit-public-key.pem`, `audit-verify.json`). The differential test finds
every `xcc-audit.db` under a kit's `evidence/`, at any depth, with the key
kept beside it under either name, and fails on a log that has no key
beside it; it writes a log under each signature suite, mutates both, and
holds `tools/auditor/verify_audit.py` and `acpctl audit verify` to the
same answer on each. `results/` holds the runs on record.

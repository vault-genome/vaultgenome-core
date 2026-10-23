# The audit logs on record, for the auditor's verifier (ADR 0034, part three)

The genuine audit logs this tree holds are the authority logs of the
region-loss drills, kept beside their keys and the product's verdict of
the day: `scripts/hardware-test/failover-region-loss/evidence/*/authority/`
(`xcc-audit.db`, `audit.pem`, `audit-verify.json`). The differential test
finds them by that path, writes a log under each signature suite, mutates
both, and holds `tools/auditor/verify_audit.py` and `acpctl audit verify`
to the same answer on each. `results/` holds the runs on record.

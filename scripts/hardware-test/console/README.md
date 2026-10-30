# console — the console on a real server, on the record

[ADR 0039](../../../docs/adr/0039-the-console-a-persons-hands-verified-on-their-computer.md).
An EC2 instance with AMD SEV-SNP, a deployment with the console's listener on,
and `vgconsole` on the machine that ran the kit, questioning the chip over the
internet: nothing on the instance is trusted to say how it went.

```bash
scripts/hardware-test/console/run.sh [region] [instance-type]   # us-east-2 m6a.xlarge by default; ~20 min; the instance is deleted at the end
KEEP=1 KEEP_PASS=./owner.vgpass KEEP_NAME="A Person" KEEP_STATE=./kept.env scripts/hardware-test/console/run.sh   # leaves it up with a fresh owner's pass
```

It needs `aws` signed in to an account with EC2 in a region that offers SEV-SNP,
`go`, `ssh`, `python3`.

What `vgconsole drill` does from here, each answer held to what it must be:

- a key on nobody's list is refused; a made-up pass is refused; the owner's pass
  opens once and is dead for anyone else;
- the chip's answer verifies here, with its provider and measurement; the same
  answer does not pass for a new question, for one bit changed in the state, for
  another listener, or against a pin one bit away;
- the journal verifies here with both services running; a changed record is
  caught and named; a removed record is caught;
- a viewer's own computer verifies the same chip, and the viewer cannot start a
  restore or press stop;
- the restore check comes back; the stop goes on, the chip's next answer says so,
  a restore is refused on the record; a list from another key and an older list
  are refused; the stop is lifted and the model comes back;
- a removed person is refused at once; the journal names every person's action.

Then `sagvd` restarts and the same pass and the same chip still prove the server
(the listener's key opened from its sealed file), both daemons stop, and the audit
log is verified here by `acpctl` and by the independent auditor.

What comes back (`evidence/<stamp>/`): `drill.out`, `drill/` (`drill.json`, the
check's challenge, state, evidence and detail, the job views, `journal-plain.json`
and `overview-*.json`, which are what a person reads), `after-restart.json`,
`audit-verify.json`, `audit-independent.json`, `audit-events.jsonl`, `guest/` with
the deployment's own record, `binaries.sha256`, `code-rev.txt`, `runner.log`,
`vm-deleted.txt`, `sha256sums.txt`. The pass never comes back; keys, seeds and the
token stay on the instance and die with it.

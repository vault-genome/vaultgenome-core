# console — the console on a real server, on the record

[ADR 0039](../../../docs/adr/0039-the-console-a-persons-hands-verified-on-their-computer.md).
Two EC2 instances with AMD SEV-SNP in two regions, a deployment with the console's
listener on each, and `vgconsole` on the machine that ran the kit, questioning both
chips over the internet and moving a model from one to the other: nothing on the
instances is trusted to say how it went.

```bash
scripts/hardware-test/console/run.sh [first-region] [second-region] [instance-type]   # us-east-2, eu-west-1, m6a.xlarge by default; ~20 min; the instances are deleted at the end
KEEP_DIR=./kept KEEP_NAME="A Person" scripts/hardware-test/console/run.sh   # no drill: both stay up with a pass each, for a person to press the buttons
scripts/hardware-test/console/destroy.sh ./kept/kept.env                    # and removes them
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
- a removed person is refused at once; the journal names every person's action;
- **the move:** the second server's chip verifies here; an order signed by another
  key, addressed to another server or out of its time is refused; the first server
  itself refuses a target one bit away from the pin, and nothing arrives; with the
  stop on it hands over nothing; then the model moves, the first server having
  verified the second's chip, and comes back EXACT on the second server by its own
  worker, its key opened from the envelope alone; a second move cannot replace it;
  the second server's journal verifies here and says so; the first server is off the
  second's list; the owner stops the old server and it refuses the model on its
  record.

Then `sagvd` restarts on the first server and the same pass and the same chip still
prove it (the listener's key opened from its sealed file), the daemons stop, and
both audit logs are verified here by `acpctl` and by the independent auditor.

What comes back (`evidence/<stamp>/`): `drill.out`, `drill/` (`drill.json`, the
check's challenge, state, evidence and detail, the job views, `move.json`, and
`journal-plain.json`, `second-journal-plain.json` and the `overview-*.json`, which are
what a person reads), `after-restart.json`, `audit-verify-*.json`,
`audit-independent-*.json`, `audit-events-*.jsonl`, `guest-first/` and `guest-second/`
with each deployment's own record, `binaries.sha256`, `code-rev.txt`, `runner.log`,
`vm-deleted.txt`, `sha256sums.txt`. This machine's address and the servers' are
replaced in the record, and the kit fails if it names the account or an IAM id. The
passes never come back; keys, seeds and the token stay on the instances and die with
them.

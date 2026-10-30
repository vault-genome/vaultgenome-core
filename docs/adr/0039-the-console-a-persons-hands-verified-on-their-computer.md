# ADR 0039 — The console: a person's hands on a deployment, verified on their own computer

- **Status:** Accepted (2026-10-30) — implemented: `cmd/vgconsole`, `internal/console`, `cmd/sagvd/console_api.go`, `acpctl console invite`, `acpctl provision --console-listen`; on real hardware in `scripts/hardware-test/console/`
- **Date:** 2026-10-30
- **Deciders:** Serhii Nikolaichuk, Rodion Sorokin
- **Extends:** ADR 0010 (the operator's stop list), ADR 0014 (the audit log), ADR 0023 (key files sealed to the host), ADR 0027 (the log in segments)
- **Amends:** audit_event schema v8 → v9 (new kind `CONSOLE_ACTION`)

## Context

Everything the product does is reachable from a terminal on the authority's
host: `acpctl`, a REST API on loopback with one bearer token, an audit log
that can only be read by pausing both daemons. A bank buys the product and the
person who answers for it — a manager, a clerk, an auditor — has none of those
and should need none of them. They have to be able to see that the model is
safe, see what was done and by whom, and press stop.

A dashboard on the server would answer the wrong question. If the server says
"all is well" on a page, a server that is not well says it too. What this
product proves is worth something only when the check is made by the one who
relies on it: on their computer, against the chip, with a question the server
could not have prepared for.

## Decision

1. **An application on the person's computer.** `vgconsole` is one Go binary
   for macOS, Windows and Linux. It serves one page, embedded in the binary,
   to the person's own browser on loopback, under a random token and a checked
   Host header, with nothing loaded from anywhere else. No Electron or Tauri:
   they bring dependencies this repository's allow-list has refused and a
   runtime nobody here has reviewed, for a window a browser already gives. The
   binary is built, hashed and signed with the release like `acpctl`.

2. **One listener on the authority.** `console.listen_address` starts a mutual
   TLS 1.3 listener in `sagvd`; empty, the default, starts nothing and changes
   nothing. Its certificate is made on the first start, its key sealed to the
   host (ADR 0023), so a restart keeps its identity. A person's key is checked
   against `console.dir/people.json`, not against a CA; a key on no list gets
   nothing past the door. The REST API stays on loopback, as it was.

3. **A pass.** A person is sent a file, `acpctl console invite` on the host or
   an owner's console having made it. It says where the server is, pins the
   listener's certificate, carries the chip's pin as the deployment's own worker
   holds it (`tee.peer`, files inline) and the audit key, and holds a single-use
   code whose hash is what the server keeps. The console makes the person's key
   on their computer; the first to open the pass is who the server admits, and
   a person who finds their pass used knows at once. A pass read by someone else
   before it is opened is that person's way in, and the record names the key.

4. **The check.** The console sends 32 random bytes. The listener answers with
   the state as bytes and the chip's evidence over the SHA-512 of a domain, the
   challenge, the listener's certificate and the state. The console verifies it
   with the same verifier code the daemons use. So the answer is fresh, comes
   from the holder of that listener's key and says exactly that state. The
   console trusts nothing of the state until this has passed, and shows a failure
   above everything it remembers.

5. **The journal.** The listener serves the live segment from the daemon's own
   open log, so nothing pauses; ADR 0027's rule stays true for `acpctl`, which
   still reads closed segments and a stopped daemon's file. The console verifies
   every record it receives: its signature under the pass's audit key, its link
   to the one before. The record the chip's last answer named must be the one
   the walk finds at that index, which a shortened journal cannot do. Records
   are shown in plain words; the steps inside a restore only when asked.

6. **People and roles.** `viewer` looks, `operator` also starts a restore check,
   `owner` also invites and removes people. The listener enforces this; the page
   only hides what would be refused. A restore check is a gate job like any other
   with `requester_identity` `person:<name>`. Whatever a person changes is a
   `CONSOLE_ACTION` event, on the chain before it takes effect; if it cannot be
   written, nothing changes.

7. **The emergency stop is ADR 0010's, unchanged in what it means.** A signed list,
   re-read at every admission, that refuses every gate job on the record. The key
   that signs it is made on the first owner's computer, and its public half is
   written when they join. The daemon verifies lists and cannot make one. Before
   that first owner, nobody holds the stop and nothing is refused for it; from
   that moment ADR 0010's rule holds: without a valid list nothing is released, an
   older serial is refused. The first owner's console signs a first list that stops
   nothing as soon as they join.

8. **A planned move is a signed order, carried out by the source and proved by
   the target.** ADR 0012 asks who decides that a model moves and answers: the
   operator, in writing. That holds here at the moment of the move. The holder
   signs an order on their computer, with the key that signs the stop list,
   naming this server, this sealed model, that server and the pin it must show;
   it is good for fifteen minutes and for one move. Their console first asks both
   chips itself. The source then does not take the console's word for the target:
   it asks the target's chip with a challenge of its own and verifies the answer
   with the pin in the order. It wraps the model's key to the escrow key that
   answer names (the key's private half sealed to that chip, ADR 0016), puts the
   release on its record, and sends the bundle, which is ciphertext, and the
   envelope. Nothing moves while the stop is on at either end, and a name already
   on the target is not replaced. The target then brings the model back by its
   own worker, under its own gate, on its own record, with the key opened from
   the envelope alone: that restore, and not the transfer, is what the person is
   shown as the move's result. For the transfer the source's listener is on the
   target's list as a `peer`, with a time limit, which may ask the chip and hand
   over a model and nothing else; the console takes it off again. `acpctl
   provision --console-listen` makes the escrow key, so any deployment with a
   console can receive.

9. **Plain words are a requirement, and a test.** No word on the page needs a
   technician. `cmd/vgconsole/console_test.go` walks every record kind, stage and
   refusal in both languages against a list of the words a person would have to
   ask about. What a platform cannot prove is shown beside what it can: on EC2 the
   chip vouches for the firmware and not for the operating system (ADR 0038), and
   the page says so and does not count it against the server.

## What this does not do

- **A move needs the old server alive.** It is for the failure known in advance.
  A server already dead or attacked is ADR 0012's: a sentinel, a replica of its
  outbox, a standby armed by a signed policy, which this console does not drive.
- **A move does not switch the bank's clients.** The model comes back on the new
  server and is proved there; the bank's traffic is the bank's to switch, and the
  dialog says so before anyone presses it. The old server keeps releasing until
  the holder stops it, which the page asks for as the last step.
- **Both servers need the same base model** for the restore to pass the gate.
- **The sealed model moves whole**, however large, over the two servers' own link;
  there is no resume yet, and a move that breaks off leaves nothing under the
  model's name on the target, so it can be pressed again.
- **The stop does not switch off the bank's model.** It refuses key releases and
  gate jobs. The dialog says so before anyone presses it. The Vault is not a model
  server (`docs/operator/00_overview.md`).
- **No second person.** One holder of the stop, no dual control, no login to a
  bank's identity provider: those wait for a buyer's own requirements.
- **The person's key is a 0600 file**, as the operator's key already is. Anyone
  with their account on that computer has their access.
- **Only the live segment is read** in the console; closed segments stay
  `acpctl`'s. The page says how many older records are in the archive.
- **Under `cnsa`** the console's Ed25519 keys are refused; it serves the general
  and `fips` profiles for now.
- **The pin comes in the pass.** Whoever can replace a pass before it arrives can
  point a person at another server; a table of known measurements in the binary
  would narrow that and is not here.

## Consequences

A deployment that sets `console.listen_address` has one more port open to whoever
the firewall lets through, in front of Go's TLS and the people list. `sagvd` gains
no authority it did not have: the stop key is not on the host, the journal is what
the log already says. Audit schema v9 means a v8 reader refuses new events; the
independent auditor (`tools/auditor`) reads v9 as it read v8, because it verifies
signatures and links and does not interpret kinds.

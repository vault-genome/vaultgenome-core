# ADR 0032 — The protocols in ProVerif: the proofs, the attacks and the assumptions

- **Status:** Proposed (2026-10-22) — part one (the cross-cloud key release: eight models) and part two (the Return Path handshake: nine models) in the tree with the recorded run and the check in CI; part three (the sentinel and the failover) follows
- **Tags:** formal, protocol, crosscloud, returnpath, failover, verification
- **Extends:** ADR 0009 and ADR 0029 (the key binding and the suites), ADR 0010 (the stop list), ADR 0011 (the receipt), ADR 0014 and ADR 0025 (the Return Path), ADR 0012 and ADR 0017 (the failover)

## Context

Every guarantee this product makes about its protocols is, today, a test of
the code and a run on hardware: the unit tests remove each check in turn
and watch a test fail (ADR 0009), the integration suite drives the daemons,
and the kits put the records in the tree (C27, C40–C44). What none of
that says is *why* a check is there — which substitution each binding
stops, which guarantee each key carries, and what every guarantee rests
on. A reader of the record can see that a swapped recipient key is refused
on the bench; it cannot see that no sequence of messages the network can
compose reaches the key, nor which line of the protocol that depends on.

The IETF work this project is part of has settled how that is said. The
TWI SIG's `tacra-verification` holds twenty-four ProVerif models of
TACRA's binding, written from one template so that the variants differ
only in the lines a pull request changes, with the tool's verdicts
recorded unedited and reproduced in CI; the drafts point to it for what
the binding guarantees and under which assumptions. The same method, on
the protocols this product runs, is what separates a tested
implementation from a reference one: a bank's reviewer, a standards
group, or a second implementer reads the model and the verdicts, not the
test names.

Three protocols carry the product's guarantees: the cross-cloud key
release (the request, the recipient key bound into the chip's quote, the
stop list and the allow-list, the token, the receipt), the Return Path
handshake (mutual attestation over nonces, the session, the signed
candidate and the signed verdict), and the policy-driven failover (the
operator's policy, the sentinel's attested records, the executor's
choice, the release that follows). Each is specified by its ADRs and by
the code; none has a model.

## Decision

1. **The protocols are modelled in ProVerif, in the tree, under
   `formal/`.** One generator (`formal/gen.py`) writes every model from
   one template per protocol, so that the variants differ only in the
   lines that change. For each protocol: the model of what the daemons
   run, and one variant per protection removed or key leaked, so that the
   verdicts state what each guarantee rests on. The models name the code
   they model, function by function (`formal/README.md`).
2. **The verdicts are recorded and checked.** `formal/results/` holds the
   tool's output unedited; `formal/check_results.py` runs ProVerif 2.05
   on the models and compares the verdicts, query by query, with the
   recorded run; `make formal-check` and the `formal` workflow — which
   builds the tool from the official tarball, pinned by digest — fail on
   any difference. A change to a protocol changes its model, its verdicts
   and this record together, or it does not merge.
3. **Assumptions and omissions are written beside the verdicts.** The
   symbolic model: the attacker is the network, no primitive breaks, a
   chip's quote is a signature with one key standing for the vendor root.
   What is not modelled is listed — the TLS between the daemons, the hash
   chain of the audit log, timeouts and table sizes — and nothing is
   claimed for it.
4. **The claim is narrow and comes last.** A model proves the protocol as
   written, not the code as shipped; the code is tied to the model by the
   tests that remove each check (ADR 0009) and, when it exists, by a
   second implementation that verifies the same records. A verifiable
   claim (C45) is written when all three parts are in the tree, and says
   exactly that.

## Part one: the cross-cloud key release (2026-10-22)

Eight models, seven queries each, 62 recorded verdicts (the first 62 lines
of `formal/results/proverif-20261022T170804Z.txt`). The release as the
daemons run it holds all seven: the released key stays secret from the
network; a key the destination opens was authorized by the source for
that decision; the source authorizes only to a key the honest destination
generated for the request, once per key; every opening corresponds to one
release; no release once the operator's stop is on the record; every
confirmation corresponds to one restore the chip vouched for; no release
to a genuine chip the operator did not list. The variants show what each
rests on: without the key in the challenge the key leaks and the binding
fails; without the suite in the challenge the key leaks under a swapped
suite while the binding holds (what ADR 0029 added); with one recipient
key for every handshake a later leak exposes the key and one token opens
on every host; without the no-rollback rule the operator's earlier list
lifts the stop; without the decision in the receipt an earlier receipt
confirms a later decision; a leaked chip key breaks everything; a leaked
authority key lets the attacker feed the destination a token of its own
and exposes nothing the honest authority released.

## Part two: the Return Path handshake (2026-10-22)

Nine models, eight queries each, 81 recorded verdicts (the rest of the same
run). The handshake over mutual TLS, as the daemons run it, holds all
eight: the sealed material and the candidate stay secret, the frame MAC
keys are not the attacker's, every admission corresponds to one quote the
honest worker's chip made over that session, the unlisted chip is never
admitted, every acceptance of the vault's quote corresponds to one quote
its chip made for that nonce, every verdict to one candidate the honest
worker produced, every candidate to one job the vault issued. The
variants separate what the attestation gives from what the TLS gives: on
an open channel the admission, the pins and the vault's quote still hold
(the nonces in the challenges are what give that; without them a quote
serves another session), while the candidate's secrecy, the MAC keys and
the one-job-per-session discipline are the TLS's — the frame MAC keys are
derived from the two nonces and the derivation context, which travel
inside the TLS, so they are secret exactly when the transcript is, and
the frame MAC binds a frame to its handshake rather than keeping a
secret of its own. The sealed material has two layers, the session
sealing key and the channel, and either keeps it. The registry key ties
a verdict to the honest worker when the channel is open; under TLS a
rogue with a certificate is never admitted, so a leaked registry key
changes nothing there. The vault's TLS key leaked is a man in the middle
who sees the candidate and replays jobs and does not open the material;
the chips' key leaked breaks the admission and nothing the TLS carries.

## Consequences

- A reviewer reads one table per protocol: which line stops which attack,
  and what the whole rests on. The ADRs that decided each binding (0009,
  0029, 0010, 0011) now have a model behind their argument.
- CI gains a job of about a minute that builds ProVerif and runs the
  models; `vault-gate` is unchanged, so a developer's machine needs no
  ProVerif unless it changes a protocol.
- The models are a specification a second implementer can write to; the
  queries are the acceptance tests of that implementation.
- What the models do not cover stays said: they prove the protocol in the
  symbolic model, under the assumptions listed, and not the code.

## Alternatives considered

- **Tamarin.** Equivalent for these properties; ProVerif is what the
  group's models use and what the drafts point to, and the models are
  read by the same people. Rejected for consistency, not on merit.
- **A separate repository, as the group keeps for TACRA.** The product's
  protocols change with the product's releases; the model, the verdicts
  and the code move in one pull request only when they live in one tree.
  Rejected.
- **Models of the code (extraction).** Out of reach for Go today; the
  tests that remove each check, and a second implementation, are the tie.
  Not rejected; later.

## References

- ProVerif 2.05, Bruno Blanchet, Vincent Cheval and Marc Sylvestre; the
  official tarball `proverif2.05.tar.gz`, sha256
  `4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4`.
- TWI-Unified-Model/tacra-verification (`formal/`, twenty-four models,
  62 recorded verdicts; the method this record follows).
- ADR 0009, 0010, 0011, 0012, 0014, 0017, 0025, 0029; `internal/vault/kms`,
  `internal/bootstrap/crosscloud`, `internal/genome/receipt`,
  `internal/contracts/{cross_cloud_handshake_request,key_release_token}`.
- RFC 9180 (HPKE); the Dolev–Yao model (1983).

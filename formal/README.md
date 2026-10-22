# The protocols in ProVerif: the proofs, the attacks and the assumptions

The formal models of the protocols the daemons run, written for ADR 0032 the way the TWI SIG's
[tacra-verification](https://github.com/TWI-Unified-Model/tacra-verification) holds the models of
TACRA: `gen.py` writes every model from one template, so that the variants differ only in the lines
that change between them; `results/` holds the ProVerif 2.05 output, unedited, of the recorded
run; `check_results.py` runs the tool and compares its verdicts, query by query, with that run.
A change to a protocol that changes a verdict fails `make formal-check` and the `formal` workflow.

Part one, this directory today: the cross-cloud key release of ADR 0009, 0029, 0010 and 0011 —
eight models, 62 recorded verdicts. The Return Path handshake (part two) and the sentinel and the
failover (part three) follow in the same form.

## The key release: what is modelled, and where it is in the code

| In the model | In the code |
|---|---|
| The source signs a request with a fresh nonce `n` and a decision id | `cross_cloud_handshake_request` (`HandshakeNonce`, `DecisionID`, `RequestID`, `KEMSuites`), signed by the authority's key; `kms.Coordinator.CoordinateRestore` |
| The destination generates a recipient key `hk` for that request alone, and its chip quotes over `h((label_bind, suite, pk, n))` | `crosscloud.Receiver.HandleHandshakeRequest`: `suite.GenerateRecipientKey`, `remember(RequestID, …)`, `localTEE.Quote(kms.RecipientChallengeV2(suite, pub, nonce))` — SHA-512 over `"vault-genome xcc-kem-bind v2"`, the suite, the key and the nonce |
| The source verifies the quote under the challenge it recomputes from the key and suite it received and its own nonce | `tee.VerifyDetailed(verifier, evidence, RecipientChallengeV2(suite, recipientPub, nonce))` |
| The operator's stop list: signed, a serial, `stop_all`; the source refuses a list older than the newest serial on its record | ADR 0010; `crosscloud.operator_stop`; the policy version `…;revocation=<serial>` |
| The allow-list on the verified measurement: `meas_ok` listed, `meas_bad` a genuine chip the operator did not list | `kms.AllowListPolicy.AuthorizeKeyRelease` |
| The authorization on the record before the token leaves | `KindKeyReleaseAuthorized`, emitted before dispatch |
| The token: signed; the key encapsulated to `pk` under the suite the answer named, with the binding as additional data | `key_release_token`: `WrappedKey.Suite`, `Ciphertext`, `AAD = SHA-256(TokenID ‖ DestinationMeasurement ‖ KeyID)`; `kms.canonicalWrapAAD` |
| The destination opens under the key of that request only, once, after the decision and the binding check | `Receiver.HandleKeyReleaseToken`: `VerifySignature`, `take(RequestID)` (single use), the `DecisionID` check, the AAD recomputed, `suite.Unwrap` |
| The receipt, quoted by the destination's chip over `h((label_rcpt, receipt))`; the source confirms the measurement it released to, the decision and the key id | `receipt.Challenge` — SHA-512 over `"vault-genome restore-receipt v1"` and the receipt; `kms.ConfirmRestore` |

Abstractions: the symbolic model (the attacker is the network and composes messages, and no
primitive breaks); a chip's quote is a signature with the chips' key `tk` — one key for every
genuine chip, standing for the vendor root — over the measurement and the challenge; HPKE is an
ideal public-key encryption with additional data; `suite_weak` is any suite the source accepts and
the destination did not generate its key for, and the attacker opens it. Not modelled: the TLS
between the daemons (the channel is the attacker's here, which is stronger than the deployment),
the hash chain of the audit log, the handshake table's TTL and size, the allow-list's shape, the
gate verdict the receipt carries, the escrow of the key before the release.

## The queries, in the order the tool prints them

| | Query | Reads |
|---|---|---|
| **S** | `attacker(dek)` | the released key stays secret |
| **A1** | `Opened(d, k) ⇒ Authorized(d, m, p)` | a key the destination opened was authorized by the source for that decision |
| **A2** | `inj Authorized(d, m, p) ⇒ inj Generated(p, n)` | the source authorizes only to a key the honest destination generated for the request, once per key |
| **A3** | `inj Opened(d, k) ⇒ inj Released(t, d, k)` | every opening corresponds to one release: no replay |
| **P** | `AuthorizedIn(ph1)` unreachable | no authorization once the operator's stop is on the record |
| **R** | `inj Confirmed(d, kid, m) ⇒ inj Restored(d, kid, m)` | every confirmation corresponds to one restore the chip vouched for |
| **M** | `Authorized(d, meas_bad, p)` unreachable | no authorization to the unlisted chip |

## The verdicts (`results/proverif-20261022T165658Z.txt`)

| model | what changes | S | A1 | A2 | A3 | P | R | M |
|---|---|---|---|---|---|---|---|---|
| `keyrelease-base.pv` | the release as the daemons run it | true | true | true | true | true | true | true |
| `keyrelease-nobind.pv` | the challenge covers the nonce alone (the derivation ADR 0009 replaced) | **false** | true | **false** | true | true | true | true |
| `keyrelease-nosuitebind.pv` | the v1 challenge of ADR 0009: the key and the nonce, not the suite | **false** | true | true | true | true | true | true |
| `keyrelease-sharedkey.pv` | one recipient key for every handshake, leaked after the release | **false** | true | true | **false** | true | true | true |
| `keyrelease-stop-rollback.pv` | the source accepts any list the operator ever signed | true | true | true | true | **false** | true | true |
| `keyrelease-receipt-nodecision.pv` | the receipt names the key and the measurement, not the decision | true | true | true | true | true | **false** | true |
| `keyrelease-tee-key-leaked.pv` | the chips' attestation key has leaked | **false** | true | **false** | true | true | **false** | true |
| `keyrelease-authority-key-leaked.pv` | the authority's signing key has leaked | true | **false** | true | **false** | true | true | true |

What the rows show. The key binding in the challenge is what keeps the released key from a
network attacker (second row: without it, the attacker puts its own key in the destination's
answer and the source releases to it). The suite in the challenge is what keeps a suite the source
accepts from being swapped in on the wire (third row: the key is still the destination's, and the
key still leaks — the source wraps under a suite the destination did not generate its key for;
ADR 0029 bound the suite for this). A recipient key made for one handshake and dropped after it
is what gives a later leak nothing (fourth row), and it is also what makes a token good for one
opening: with one key on every host, one token opens on each (A3). The stop list's no-rollback
rule is the whole of the stop (fifth row: without it the list the operator signed before the stop
lifts it). The decision in the receipt is what ties a confirmation to one restore (sixth row:
without it a receipt of an earlier restore of the same key confirms a later decision). The two
last rows are the assumptions: a leaked chip key breaks everything, which is what the protocol
rests on; a leaked authority key lets the attacker feed the destination a token of its own (A1,
A3) and does not expose the key the honest authority released (S).

## Reproduce

ProVerif 2.05 on PATH, or `PROVERIF=/path/to/proverif` (built from
`https://proverif.inria.fr/proverif2.05.tar.gz`, sha256
`4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4`, with `./build -nointeract`,
which needs only an OCaml compiler; the eight models take about a second):

    make formal-check        # the models are what gen.py writes; the verdicts are the recorded ones
    make formal              # a new recorded run in formal/results/

The `formal` workflow (`.github/workflows/formal.yml`) does the same on every push, with the tool
built from the tarball by digest.

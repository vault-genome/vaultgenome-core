# The protocols in ProVerif: the proofs, the attacks and the assumptions

The formal models of the protocols the daemons run, written for ADR 0032 the way the TWI SIG's
[tacra-verification](https://github.com/TWI-Unified-Model/tacra-verification) holds the models of
TACRA: `gen.py` writes every model from one template, so that the variants differ only in the lines
that change between them; `results/` holds the ProVerif 2.05 output, unedited, of the recorded
run; `check_results.py` runs the tool and compares its verdicts, query by query, with that run.
A change to a protocol that changes a verdict fails `make formal-check` and the `formal` workflow.

Three protocols, in this directory: the cross-cloud key release of ADR 0009, 0029, 0010 and 0011
(eight models), the Return Path handshake of ADR 0014 and 0025 (nine models), and the sentinel and
the failover of ADR 0012 and 0017 (six models) — twenty-three models, 185 recorded verdicts
(`results/proverif-20261022T173929Z.txt`).

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

## The verdicts: the key-release models

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

## The Return Path handshake: what is modelled, and where it is in the code

| In the model | In the code |
|---|---|
| The worker opens a mutual-TLS connection to the vault with its certificate; the vault requires one | `cmd/sagvd/daemon.go` (`tls.RequireAndVerifyClientCert`), the client certificates of `acp-keygen`; abstracted as a fresh connection key sent under the vault's certificate key, authenticated by the worker's |
| HELLO_CLIENT: a fresh nonce and a proposed challenge | `transport.HelloClient` (`ClientNonce`, `ProposedChallenge`) |
| HELLO_SERVER: the nonce echoed, the vault's nonce, the vault's chip quote over `h((labelS, nc, prop))`, the derivation context | `transport.HelloServer`; `transcriptServerChallenge` — SHA-256 over `"rp-wire-v1.0 SERVER-ATT"`, the client nonce and the proposed challenge |
| The worker verifies the vault's quote at the vault's pinned measurement | `verifyPeerRecord` with the client's `Verifier` configured for the vault's family and measurement |
| ATTEST_CLIENT: the worker's chip quote over `h((labelC, nc, ns, ctx))`; the vault verifies it at the worker's pinned measurement and admits the session | `transcriptClientChallenge` — `"rp-wire-v1.0 CLIENT-ATT"`, both nonces and the context; `server.Config.Verifier`, "configured with the worker's expected Measurement" |
| The frame MAC keys: HKDF over the two nonces and the context | `deriveSessionKeys` (IKM = client nonce ‖ server nonce, salt `"rp-wire-v1.0 hkdf-salt"`, info `"rp-wire-v1.0 session-mac"` ‖ context); `Conn.Write` and `Conn.Read`, HMAC-SHA-256 |
| The job: the manifest, and the material sealed under the session sealing key with the manifest as additional data | `transport.JobRequest` and `SealedMaterialRef` (nonce, ciphertext, AAD); `keys.session_sealing`, shared by the daemons and sealed to each host (ADR 0023); `client.Opener` |
| The candidate, signed by the worker's registry key over its cover | `CandidateOutputFrame.CoverBytes` (every field but the signature), `worker_signature_alg`; `server.Session.verifyWorkerSignature` under the registry's key and suite (ADR 0031) |
| The verdict, signed by the authority, naming the candidate by digest | `signVerdict` over `Verdict.CanonicalBytes()`; the audit record carries the candidate's digest (ADR 0014) |

Abstractions, beside those of part one: the TLS is a fresh key under the vault's certificate key,
authenticated by the client's; a certificate the vault accepts is in the attacker's hands (the
rogue of the kits); the proposed challenge is a fresh value; the job's material is one sealed
value; the gate's judgement is the event `Judged`. Not modelled: TLS's own handshake and record
sequence numbers (a frame replayed within one connection is read once, in order, by the process);
the heartbeat and shutdown frames; the audit events; the registry's shape (one key, `kidW`); the
session's deadline.

| | Query | Reads |
|---|---|---|
| **S** | `attacker(payload)` | the sealed material stays secret |
| **C** | `attacker(new cand)` | the candidate stays secret |
| **K** | `attacker(new probe)` | a value sealed under the frame MAC key stays secret: the MAC keys are not the attacker's |
| **W** | `inj Admitted(mw, nc, ns, ctx) ⇒ inj WorkerQuoted(nc, ns, ctx)` | every admission corresponds to one quote the honest worker's chip made over that session |
| **M** | `Admitted(meas_bad, …)` unreachable | no admission of the unlisted chip |
| **V** | `inj VaultVerified(mv, nc, prop) ⇒ inj VaultQuoted(nc, prop)` | every acceptance of the vault's quote corresponds to one quote its chip made for that nonce |
| **J** | `inj Judged(mf, cand) ⇒ inj Produced(mf, cand)` | every verdict corresponds to one candidate the honest worker produced for that manifest |
| **I** | `inj Produced(mf, cand) ⇒ inj Issued(mf)` | every candidate the worker produced corresponds to one job the vault issued |

## The verdicts: the Return Path models

| model | what changes | S | C | K | W | M | V | J | I |
|---|---|---|---|---|---|---|---|---|---|
| `returnpath-base.pv` | the handshake over mutual TLS, as the daemons run it | true | true | true | true | true | true | true | true |
| `returnpath-notls.pv` | the same on an open channel | true | **false** | **false** | true | true | true | true | **false** |
| `returnpath-notls-nononce.pv` | on an open channel, the nonces left out of the chips' challenges | true | **false** | **false** | **false** | true | **false** | true | **false** |
| `returnpath-notls-sealing-key-leaked.pv` | on an open channel, the session sealing key leaked | **false** | **false** | **false** | true | true | true | true | **false** |
| `returnpath-notls-worker-signing-key-leaked.pv` | on an open channel, the worker's registry key leaked | true | **false** | **false** | true | true | true | **false** | **false** |
| `returnpath-sealing-key-leaked.pv` | over TLS, the session sealing key leaked | true | true | true | true | true | true | true | true |
| `returnpath-worker-signing-key-leaked.pv` | over TLS, the worker's registry key leaked | true | true | true | true | true | true | true | true |
| `returnpath-vault-tls-key-leaked.pv` | the vault's TLS certificate key leaked | true | **false** | **false** | true | true | true | true | **false** |
| `returnpath-tee-key-leaked.pv` | the chips' attestation key leaked | true | true | true | **false** | true | true | true | true |

What the rows show. The attestation and the pins do not rest on the TLS: on an open channel the
vault still admits only a session the honest worker's chip quoted over, and the worker still
accepts only the vault's chip's quote for its nonce (second row, W, M, V) — the nonces in the two
challenges are what give that (third row: without them a quote serves another session, W and V).
What the TLS gives is the rest of the session: the candidate's secrecy, the frame MAC keys —
derived from the two nonces and the context, so secret exactly when the transcript is — and the
one-job-per-session discipline against a replayed frame (second row, C, K, I). The sealed material
has two layers, and either keeps it: the sealing key leaked under TLS, or the channel open with
the key intact, leaves S true; both gone leaves it false (fourth, sixth and second rows). The
registry key is what ties a verdict to the honest worker when the channel is open (fifth row, J);
under TLS a leaked registry key changes nothing, because a rogue with a certificate is never
admitted (seventh row). The vault's TLS key leaked is a man in the middle: the candidate and the
MAC keys are its, and it replays jobs, while the material stays sealed (eighth row). The chips'
key leaked breaks the admission and nothing the TLS carries (last row).

## The sentinel and the failover: what is modelled, and where it is in the code

| In the model | In the code |
|---|---|
| The operator's failover policy: its serial, the sentinel's key, the primary's measurement, the one standby's measurement, signed by the operator's key | `vault-genome/failover-policy/v1` (`acpctl failover issue`): `serial`, `sentinel_public_key`, `primary.kind` and `primary.measurements` (ADR 0017), `standby.measurements`; the operator key of `crosscloud.operator_stop` |
| The sentinel seals a generation: the genome key encapsulated to the authority's escrow key, the seal record signed with the sentinel's key and quoted by the primary's chip over the record | `acpctl sentinel watch --tee`: the v3 bundle, the escrow envelope to the authority's escrow key (ADR 0011), the seal record with its `attestation` — `REPORT_DATA` bound to the record's content (ADR 0017 §1) |
| The compromise report, naming the last generation sealed, signed and quoted the same way; it carries a standby the executor ignores | the compromise report of ADR 0012; ADR 0017 §1 and §3 |
| The executor verifies the policy under the operator's key, accepts from the outbox only records under the policy's sentinel key that carry the primary chip's quote at the pinned measurement, acts on the trigger, and chooses the generation the report names whose bundle hashes to its record | `sagvd failover` (`internal/vault/failover`): `Arm`, `Watch`, `Choose`; unattested records ignored (ADR 0017 §1), nothing past the sentinel's last word (§3) |
| The decision on the record, the key opened from escrow, the attested release of part one to the standby the policy names, under the operator's stop list | `FAILOVER_DECIDED`; the release policy `stop list ⟶ failover policy ⟶ allow-list` (ADR 0012) |
| The standby: the destination of part one, at the measurement the policy names | `acp-bootstrap`, `crosscloud.Receiver` |

Abstractions, beside those of parts one and two: one generation and one policy serial; the chain
is one seal record and one report; the executor's clock — the quarantine, the RPO bound, the
heartbeat timeout, the `stopped` grace, the policy's validity window — is not modelled; the
receipt and the confirmation are part one's; the allow-list admits the standby. Two rules are the
authority's record rather than the protocol, and the symbolic model does not establish them: that
one policy serial performs at most one failover, and that an older serial is refused (both read
from the verified audit log at arming). The models of the compromised primary carry no phase 1,
so their **P** is vacuous.

| | Query | Reads |
|---|---|---|
| **G** | `attacker(kg)` | the genome key stays secret: the primary and the outbox hold ciphertext |
| **F1** | `Decided(ser, g) ⇒ PolicyIssued(ser)` | every failover corresponds to a policy the operator issued |
| **F2** | `Released(ser, m) ⇒ PolicyNames(ser, m)` | the key is released only to the measurement the policy names — not the primary's, the model's or the outbox's choice |
| **F3** | `Decided(ser, g) ⇒ SentinelReported(g)` | every trigger acted on is a report the sentinel wrote on its chip |
| **F4** | `Chosen(g) ⇒ SentinelSealed(g)` | every generation chosen is one the sentinel sealed on its chip |
| **F5** | `Opened(ser, k) ⇒ Decided(ser, g)` | every opening on the standby corresponds to a decision |
| **P** | `AuthorizedIn(ph1)` unreachable | no release once the operator's stop is on the record |

## The verdicts: the failover models

| model | what changes | G | F1 | F2 | F3 | F4 | F5 | P |
|---|---|---|---|---|---|---|---|---|
| `failover-base.pv` | the sentinel and the failover as the daemons run them | true | true | true | true | true | true | true |
| `failover-seed-leaked.pv` | the sentinel's seed leaked and used off the chip | true | true | true | true | true | true | true |
| `failover-seed-leaked-nopin.pv` | the seed leaked, and the policy does not pin the primary's chip (ADR 0012 without ADR 0017) | true | true | true | **false** | **false** | true | true |
| `failover-primary-compromised.pv` | the primary is the attacker's: the seed and its chip's quotes | true | true | true | **false** | **false** | true | (vacuous) |
| `failover-primary-compromised-worm.pv` | the primary is the attacker's, and the executor takes the standby from the report | **false** | true | **false** | **false** | **false** | true | (vacuous) |
| `failover-tee-key-leaked.pv` | the chips' attestation key leaked | **false** | true | true | true | true | true | true |

What the rows show. The operator's policy is what keeps a worm out: with the primary in the
attacker's hands — its sentinel's seed and its chip's quotes — the attacker can trigger a failover
and name the genome (F3, F4: the primary's word is its own, the limit ADR 0012 states), and the
key still goes only where the policy says and stays secret (F2, G; fourth row); let the executor
take the standby from the report instead, and the key goes wherever the primary points (fifth
row). The chip's quote over every record is what makes a stolen seed worthless off the chip
(second row against the third: ADR 0017). The escrow is what keeps the key from the primary and
the outbox (G, every row but the worm's and the chip key's). The chips' key leaked lets an
impostor stand in for the standby (last row).

## Reproduce

ProVerif 2.05 on PATH, or `PROVERIF=/path/to/proverif` (built from
`https://proverif.inria.fr/proverif2.05.tar.gz`, sha256
`4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4`, with `./build -nointeract`,
which needs only an OCaml compiler; the twenty-three models take a few seconds):

    make formal-check        # the models are what gen.py writes; the verdicts are the recorded ones
    make formal              # a new recorded run in formal/results/

The `formal` workflow (`.github/workflows/formal.yml`) does the same on every push, with the tool
built from the tarball by digest.

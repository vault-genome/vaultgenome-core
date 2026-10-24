# Reference design 01 on real SEV-SNP — the run of 20261023T222209Z

Profile `general` (ADR 0029), the key encapsulated under `hpke-x25519-v2`. The bank: `vg-rd01-bank-20261023t222209z zone=us-central1-c ip=10.128.15.204`; the standby: `vg-rd01-standby-20261023t222209z zone=europe-west4-b ip=10.164.15.232`. Tree `84cc9b91e590`.
The bank's chip: measurement `9fc6d42b3005958a…`; the standby's: `0e017d2fba7c4964…`.

## A job, end to end (the design's six steps)

| Step | Result | Where |
| - | - | - |
| 1. The quant seals the fine-tune (`acpctl genome seal`) | **ok** | `a/seal.json`, key id `genome-e7063d3cebec-g0-d8032c3e2d2f` |
| 2. The operator submits the job; `REQUEST_RECEIVED` first | **ok** | `a/job-submit.json`, request `req-cc2b65f2efe9c91d` |
| 3. The worker's session: the handshake with both chips' reports, `TRUST_EVALUATED` | **ok** | `a/session-opened.json`, handshake 8210 ms |
| 4. The material released for the session; the model restored in memory, the fixtures run | **ok** | `a/job.json`: gate EXACT, 6 of 6 fixtures, `max_abs_err` 0 |
| 5. The signed verdict; `RELEASE_DECIDED` closes the job | **ok** | signer `sagvd-authority-e2e`; `a/audit-events.jsonl` |
| 6. The third party verifies the chain and queries the request (`acpctl audit verify`, `audit query --request`, `lineage`) | **ok** | `third-party/steps.txt`: 4 lines at exit 0 |

## The continuity, and what was refused

| What | Result | Where |
| - | - | - |
| The standby attests with its chip; its measurement on the bank's allow-list | **ok** | `b/destination-identity.json`; `a/standby.json` |
| The genome's key released to the standby in region B after its report verified (`sagvd crosscloud-restore`) | **ok** | `a/release.json`: suite `hpke-x25519-v2`, profile `general` |
| The standby restores by itself; the restore confirmed from its chip-signed receipt (`crosscloud-confirm`) | **ok** | `a/confirm.json`, `b/receipt.json` |
| The restored model gated on the standby's chip against the sealed fixtures (`acpctl genome gate`) | **ok** | `b/standby-gate.json`: EXACT, 6 fixtures, backend 4.40715146 s |
| A release to a guest not on the allow-list refused | **ok** | `a/steps.txt`: 1 policy denied key release: destination measurement not in allow-list for |
| A release under the operator's stop refused | **ok** | `a/steps.txt`: 1 policy denied key release: operator stop in force |
| A thief with the sealed key files, off the chip: they do not open | **ok** | `a/rogue-sealed-worker.log` |
| A worker that is not the pinned identity refused at the handshake | **ok** | `a/rogue-worker.log`, `a/sagvd.log` |
| Both audit logs verified under the published key | **ok** | `a/audit-verify.json` 17 events, `a/xcc-audit-verify.json` 10 events |

## The figures, from this run

| Quantity | This run | The design's reference | Where |
| - | - | - | - |
| Handshake, SEV-SNP, the first report of a boot | 8210 ms | about 10 s (C32; T6) | `a/sagvd.handshake_ms.txt` |
| Handshake, subsequent sessions | 24 ms | 21–50 ms (T6) | `a/sagvd.handshake_ms.txt` |
| A gate job on a CPU worker (small model, 6 fixtures) | 5.2 s | 4–5 s (T1, T2, T7) | `a/timeline.txt` |
| The key released to the attested standby and its restore confirmed | 15.6 s | — (new in this kit) | `a/timeline.txt` |
|   of which the release itself (handshake, report verified, key wrapped) | 4.9 s |  | `a/timeline.txt` |
|   the standby: key received to genome restored | 0.004 s |  | `a/confirm.json` |
| The restored model gated on the standby's chip | 4.4 s | — (new in this kit) | `b/timeline.txt`, `b/standby-gate.json` |
| The worker runtime from the hash-pinned locks (the bank; pip alone) | 44.3 s | 72–83 s (release records) | `a/timeline.txt` |
|   and the guest's apt before it (the image's own updates hold the lock) | 31.3 s |  | `a/timeline.txt` |
| The standby's runtime from the locks (pip alone) | 44.1 s |  | `b/timeline.txt` |
| The fine-tune (tiny model, 20 steps) | 9.6 s | 8–10 s (release records) | `a/timeline.txt` |
| The bank's guest, start to record | 166.9 s |  | `a/steps.txt` |
| The standby's guest, start to record | 181.9 s |  | `b/steps.txt` |
| The whole run to the third party's verdict, this machine's clock (the guests' creation included) | 313.0 s |  | `runner-timeline.txt` |

The design's reference figures are the test hardware's (docs/reference-designs/01-tier1-bank-model-continuity.md); the ones above are this run's, on the machines named. Neither is a service level.

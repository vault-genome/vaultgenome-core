# Reference design 01 on real SEV-SNP — the run of 20261021T202252Z

Profile `fips` (ADR 0029), the key encapsulated under `hpke-p384-v2`. The bank: `vg-rd01-bank-20261021t202252z zone=us-central1-c ip=10.128.15.232`; the standby: `vg-rd01-standby-20261021t202252z zone=europe-west4-b ip=10.164.0.2`. Tree `b0ee2a5c8a4a`.
The bank's chip: measurement `7dc7c12e55999ef4…`; the standby's: `0e017d2fba7c4964…`.

## A job, end to end (the design's six steps)

| Step | Result | Where |
| - | - | - |
| 1. The quant seals the fine-tune (`acpctl genome seal`) | **ok** | `a/seal.json`, key id `genome-c8a81cc3c0a1-g0-dd432924171e` |
| 2. The operator submits the job; `REQUEST_RECEIVED` first | **ok** | `a/job-submit.json`, request `req-cf7094ae1471f8db` |
| 3. The worker's session: the handshake with both chips' reports, `TRUST_EVALUATED` | **ok** | `a/session-opened.json`, handshake 8205 ms |
| 4. The material released for the session; the model restored in memory, the fixtures run | **ok** | `a/job.json`: gate EXACT, 6 of 6 fixtures, `max_abs_err` 0 |
| 5. The signed verdict; `RELEASE_DECIDED` closes the job | **ok** | signer `sagvd-authority-e2e`; `a/audit-events.jsonl` |
| 6. The third party verifies the chain and queries the request (`acpctl audit verify`, `audit query --request`, `lineage`) | **ok** | `third-party/steps.txt`: 4 lines at exit 0 |

## The continuity, and what was refused

| What | Result | Where |
| - | - | - |
| The standby attests with its chip; its measurement on the bank's allow-list | **ok** | `b/destination-identity.json`; `a/standby.json` |
| The genome's key released to the standby in region B after its report verified (`sagvd crosscloud-restore`) | **ok** | `a/release.json`: suite `hpke-p384-v2`, profile `fips` |
| The standby restores by itself; the restore confirmed from its chip-signed receipt (`crosscloud-confirm`) | **ok** | `a/confirm.json`, `b/receipt.json` |
| The restored model gated on the standby's chip against the sealed fixtures (`acpctl genome gate`) | **ok** | `b/standby-gate.json`: EXACT, 6 fixtures, backend 3.962869227 s |
| A release to a guest not on the allow-list refused | **ok** | `a/steps.txt`: 1 policy denied key release: destination measurement not in allow-list for |
| A release under the operator's stop refused | **ok** | `a/steps.txt`: 1 policy denied key release: operator stop in force |
| A thief with the sealed key files, off the chip: they do not open | **ok** | `a/rogue-sealed-worker.log` |
| A worker that is not the pinned identity refused at the handshake | **ok** | `a/rogue-worker.log`, `a/sagvd.log` |
| Both audit logs verified under the published key | **ok** | `a/audit-verify.json` 17 events, `a/xcc-audit-verify.json` 10 events |

## The figures, from this run

| Quantity | This run | The design's reference | Where |
| - | - | - | - |
| Handshake, SEV-SNP, the first report of a boot | 8205 ms | about 10 s (C32; T6) | `a/sagvd.handshake_ms.txt` |
| Handshake, subsequent sessions | 26 ms | 21–50 ms (T6) | `a/sagvd.handshake_ms.txt` |
| A gate job on a CPU worker (small model, 6 fixtures) | 5.2 s | 4–5 s (T1, T2, T7) | `a/timeline.txt` |
| The key released to the attested standby and its restore confirmed | 15.6 s | — (new in this kit) | `a/timeline.txt` |
|   of which the release itself (handshake, report verified, key wrapped) | 4.9 s |  | `a/timeline.txt` |
|   the standby: key received to genome restored | 0.006 s |  | `a/confirm.json` |
| The restored model gated on the standby's chip | 4.0 s | — (new in this kit) | `b/timeline.txt`, `b/standby-gate.json` |
| The worker runtime from the hash-pinned locks (the bank; pip alone) | 45.8 s | 72–83 s (release records) | `a/timeline.txt` |
|   and the guest's apt before it (the image's own updates hold the lock) | 30.6 s |  | `a/timeline.txt` |
| The standby's runtime from the locks (pip alone) | 41.4 s |  | `b/timeline.txt` |
| The fine-tune (tiny model, 20 steps) | 10.2 s | 8–10 s (release records) | `a/timeline.txt` |
| The bank's guest, start to record | 168.0 s |  | `a/steps.txt` |
| The standby's guest, start to record | 186.5 s |  | `b/steps.txt` |
| The whole run to the third party's verdict, this machine's clock (the guests' creation included) | 316.0 s |  | `runner-timeline.txt` |

The design's reference figures are the test hardware's (docs/reference-designs/01-tier1-bank-model-continuity.md); the ones above are this run's, on the machines named. Neither is a service level.

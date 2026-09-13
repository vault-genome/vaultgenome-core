# Positioning Doctrine Rollout Log

**Doctrine reference:** `docs/doctrine/positioning.md` v1.0 (2026-04-20)
**Scope of this pass:** External-facing DOCX and top-level PDF artifacts at workspace root.
**Actor:** Stage-A governance rollout.
**Date:** 2026-04-20.

This log exists to satisfy `docs/doctrine/positioning.md §6.2 (Treatment of existing material)`:
every artifact produced before v1.0 of the doctrine must be audited against §4
(banned constructions) and one of three treatments applied — **replace**, **retire**,
or **annotate**. This file is the audit trail for that sweep.

## 1. Scan coverage

### 1.1 DOCX artifacts (9 originals scanned)

| # | File | Scan method | Hits (§4 banned constructions) |
| - | - | - | - |
| 1 | `8. Cursor-Oriented Module Task Plan.docx` | `pandoc -t plain` + regex | 0 |
| 2 | `Foundation Technical Architecture Document.docx` | `pandoc -t plain` + regex | 1 |
| 3 | `Hardware Reference Architecture Document.docx` | `pandoc -t plain` + regex | 0 |
| 4 | `MVP Technical Implementation Package.docx` | `pandoc -t plain` + regex | 0 |
| 5 | `Pseudocode and Control Logic Package.docx` | `pandoc -t plain` + regex | 0 |
| 6 | `Software Reference Architecture Document.docx` | `pandoc -t plain` + regex | 0 |
| 7 | `Technical Review Addendum.docx` | `pandoc -t plain` + regex | 0 |
| 8 | `WHITE PAPER.docx` | `pandoc -t plain` + regex | 5 |
| 9 | `рынок AI.docx` | `pandoc -t plain` + regex | 1 |

**Clean DOCX (7):** items 1, 3, 4, 5, 6, 7 above — no banned constructions detected.
**Dirty DOCX (3):** items 2, 8, 9 — listed with treatment in §2.

### 1.2 PDF artifacts (8 top-level PDFs scanned)

| # | File | Scan method | Hits |
| - | - | - | - |
| 1 | `1. AI-Continuity-Platform.pdf` | `pdftotext` + regex | 0 |
| 2 | `2. WHITE PAPER.pdf` | `pdftotext` + regex | mirrors WHITE PAPER.docx pre-edit |
| 3 | `3. Foundation Technical Architecture Document.pdf` | `pdftotext` + regex | mirrors Foundation.docx pre-edit |
| 4 | `4. Hardware Reference Architecture Document.pdf` | `pdftotext` + regex | 0 |
| 5 | `5. Software Reference Architecture Document.pdf` | `pdftotext` + regex | 0 |
| 6 | `6. MVP Technical Implementation Package.pdf` | `pdftotext` + regex | 0 |
| 7 | `7. Pseudocode and Control Logic Package.pdf` | `pdftotext` + regex | 0 |
| 8 | `8. Cursor-Oriented Module Task Plan.pdf` | `pdftotext` + regex | 0 |

Treatment for the PDFs that mirror dirty DOCX is **annotate-and-supersede**: the PDFs
are not re-rendered in this pass; the corresponding `v2.docx` file is the source of truth,
and both will be re-exported to PDF at next release cut (see §3).

## 2. Dirty-file treatment ledger

### 2.1 `Foundation Technical Architecture Document.docx` → `Foundation Technical Architecture Document v2.docx`

**Treatment:** replace (§6.2.a).

| Locus | Before | After |
| - | - | - |
| Line 1222, `document.xml` | "In this sense, the architecture introduces a new paradigm for AI systems: one in which intelligence is treated as a protected, portable, and regenerable capability rather than as a static collection of stored parameters." | "Operationally, the architecture positions intelligence as a protected, portable, and regenerable capability rather than as a static collection of stored parameters — the Governed AI Continuity model, distinct from but adjacent to disaster recovery, key management, and MLOps." |

Replacement basis: `docs/doctrine/positioning.md §4` row "new paradigm" → "operationalizes Governed AI Continuity"; §3 market-category form used verbatim for adjacency clause.
Pack validation: PASSED (paragraph count preserved).

### 2.2 `WHITE PAPER.docx` → `WHITE PAPER v2.docx`

**Treatment:** replace (§6.2.a). Five edits, all to `<w:t>` runs in `document.xml`.

| # | Line | Before | After |
| - | - | - | - |
| 1 | 1045 | "This architecture defines a new category of AI infrastructure." | "This architecture defines Governed AI Continuity as a distinct infrastructure category — adjacent to disaster recovery, key management, and MLOps, but not a subset of any of them." |
| 2 | 1563 | "They do not define a new category of AI infrastructure capable of true continuity…" | "They do not constitute a Governed AI Continuity layer capable of true continuity…" |
| 3 | 1884 | "This approach defines a new category of AI infrastructure." | "This approach operationalizes Governed AI Continuity." |
| 4 | 2272 | "This design defines a new category of AI infrastructure." | "This design realizes the Governed AI Continuity layer." |
| 5 | 5113 | "…to a new category of critical AI infrastructure." | "…to a production-grade Governed AI Continuity layer for critical AI systems." |

Post-edit verification (`pandoc -t plain` on `WHITE PAPER v2.docx`):
- "Governed AI Continuity" mentions: 5
- "new category" residuals: 0
- Pack validation: PASSED (paragraph count preserved).

### 2.3 `рынок AI.docx` → `рынок AI v2.docx`

**Treatment:** replace (§6.2.a).

| Locus | Before | After |
| - | - | - |
| Line 632, `document.xml` | "И это уже не красивая идея. Это новый рынок." | "И это уже не красивая идея. Это самостоятельный инфраструктурный слой — Governed AI Continuity, смежный с disaster recovery, key management и MLOps, но не являющийся подмножеством ни одного из них." |

Replacement basis: `docs/doctrine/positioning.md §4` row "новый рынок / новая категория" → RU market-category form from §3; adjacency clause retained to preserve the original rhetorical beat.
Pack validation: PASSED (paragraph count preserved).

## 3. Downstream obligations

1. **PDF re-export — CLOSED 2026-04-20.** `2. WHITE PAPER.pdf` and `3. Foundation Technical Architecture Document.pdf` have been re-rendered from `WHITE PAPER v2.docx` and `Foundation Technical Architecture Document v2.docx` respectively, using `soffice --headless --convert-to pdf` (LibreOffice 26.2.2.2). The pre-doctrine PDFs have been moved to `archive/pre_doctrine/` with a `(pre-doctrine, do-not-distribute)` suffix in the filename; the canonical numbered slots `2.` and `3.` now resolve to the doctrine-clean v2 renders. Post-render PDF re-scan: zero §4 residuals in either file; "Governed AI Continuity" appears 5× in the new `2. WHITE PAPER.pdf` and 1× in the new `3. Foundation Technical Architecture Document.pdf` (one mention line-wrapped by the PDF layout as "Governed AI / Continuity model" — semantically intact). See §6 for the re-export ledger.
2. **Distribution rule.** External readers receive the canonical numbered files (`2. WHITE PAPER.pdf` / `3. Foundation Technical Architecture Document.pdf`) or the `v2.docx` sources. Pre-doctrine binaries remain under `archive/pre_doctrine/` and are not shipped.
3. **Post-edit doctrine audit.** All three v2 DOCX files and both re-rendered PDFs were re-scanned after generation. No residual §4 construction remained in any of them.
4. **Future artifacts.** From 2026-04-20 onward, every new external-facing artifact must cite `docs/doctrine/positioning.md` in its front-matter and pass the §4 scan before release.

## 4. Summary

- **Artifacts scanned:** 9 DOCX + 8 top-level PDF = 17 files.
- **Artifacts with §4 hits:** 3 DOCX (2 PDFs mirror them and were re-rendered from the corresponding v2 DOCX per §6 below).
- **Replacements applied:** 7 (5 in WHITE PAPER, 1 in Foundation, 1 in рынок AI).
- **v2 DOCX produced:** 3 (`WHITE PAPER v2.docx`, `Foundation Technical Architecture Document v2.docx`, `рынок AI v2.docx`).
- **v2 PDFs promoted to canonical slots:** 2 (`2. WHITE PAPER.pdf`, `3. Foundation Technical Architecture Document.pdf`).
- **Pre-doctrine PDFs archived:** 2 (under `archive/pre_doctrine/`).
- **Retractions / annotations applied:** 0 (all dirty files were §6.2.a replace-class).
- **Outstanding items:** none.

## 5. Change log

| Date | Version | Change |
| - | - | - |
| 2026-04-20 | 1.0 | Initial rollout pass — doctrine v1.0 applied to 17 artifacts, 3 v2 DOCX produced. |
| 2026-04-20 | 1.1 | PDF re-export from v2 DOCX completed; pre-doctrine PDFs archived; canonical numbered slots `2.` / `3.` now doctrine-clean. Closes §3.1. |

## 6. PDF re-export ledger

**Tool:** `soffice --headless --convert-to pdf --outdir .` (LibreOffice 26.2.2.2 620 Build 2).
**Date:** 2026-04-20.

| Source (v2 DOCX) | Rendered to | Pre-doctrine PDF archived as | Size | §4 residuals | "Governed AI Continuity" mentions (PDF) |
| - | - | - | - | - | - |
| `WHITE PAPER v2.docx` | `2. WHITE PAPER.pdf` | `archive/pre_doctrine/2. WHITE PAPER (pre-doctrine, do-not-distribute).pdf` | 791 KB | 0 | 5 (lines 58, 148, 185, 227, 543–544 of `pdftotext` output) |
| `Foundation Technical Architecture Document v2.docx` | `3. Foundation Technical Architecture Document.pdf` | `archive/pre_doctrine/3. Foundation Technical Architecture Document (pre-doctrine, do-not-distribute).pdf` | 1,665 KB | 0 | 1 (lines 262–263 of `pdftotext` output, "the Governed AI / Continuity model") |

**Verification commands used:**

```bash
# 1. Confirm the banned-construction regex returns nothing
pdftotext "2. WHITE PAPER.pdf" - | grep -E -i "new category of AI|no analogs|…"
pdftotext "3. Foundation Technical Architecture Document.pdf" - | grep -E -i "…"

# 2. Confirm the canonical market-category phrase is intact
pdftotext "2. WHITE PAPER.pdf" - | grep "Governed AI Continuity"
pdftotext "3. Foundation Technical Architecture Document.pdf" - | grep -C 1 "Governed\|Continuity model"
```

Line-wrap caveat: `pdftotext` emits the Foundation mention across two lines
("Governed AI" \n "Continuity model") because the PDF layout line-wrapped at
that position. This is a rendering artifact of the extraction tool, not a
defect in the PDF — the phrase is continuous in the rendered PDF itself.

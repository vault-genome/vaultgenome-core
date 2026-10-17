# Compliance — the controls, and what they contribute per sector

This directory answers the question a buyer's risk function asks after
the engineering review: *for the requirements we are held to, what does
this software do, where is the proof, and what remains ours?*

| File | What it is |
| - | - |
| [`controls.md`](controls.md) | The control catalogue: every thing the software does by construction, with its decision record, its code home, its proof (a claim with evidence, a trial row, a test in the gate), its trust boundary and its limit. The sector maps refer to it by identifier (`VG-nnn`). |
| [`openssf-best-practices.md`](openssf-best-practices.md) | The OpenSSF Best Practices badge criteria, each mapped to where it is met in the tree — the one assurance mark the project pursues directly. |

Sector maps are written one at a time, each after the primary texts
have been read in full and the catalogue has been checked against the
released code: banking first (October 2026, in its own pull request),
then government, then business, then defence. A sector that is not
here yet has no map, not an implied one.

## What these documents are, and are not

They are the technical half of a conversation with a buyer's
compliance team: a control with its proof, next to the requirement it
serves. They are not a certification, an attestation or a statement
of conformity. No audit of the maintainers' organisation has been
commissioned, and the words "compliant" and "certified" do not appear
in the maps. The regulations are addressed to the institutions that
run the software; the institution meets them with its own policies,
people and processes, of which a deployment of this software is one
component. Each map ends with the short list of what the institution
must do itself.

Certification, when a buyer requires it, is a paid engagement on the
maintainers' organisation — SOC 2, ISO/IEC 27001 — with months of
operational evidence, and is pursued when a buyer requires it, not
before. The badge is the exception: it is earned on the tree and costs
nothing but the work.

## How to use them

- **Before a buyer conversation**: read the sector map, then the rows
  of `controls.md` it cites, then the claims and trial rows those cite.
  Every number in the maps is in a record under
  [`VERIFIABLE-CLAIMS.md`](../../VERIFIABLE-CLAIMS.md) or
  [`TRIAL-2026-10.md`](../TRIAL-2026-10.md).
- **For a security questionnaire**: the catalogue answers the questions
  about the software; the questions about the organisation (screening,
  training, insurance, incident reporting) are answered from the
  maintainers' own records, not from this directory.
- **For an auditor**: the maps cite article and paragraph numbers of
  the published texts; the texts themselves are the auditor's own
  copies. PCI DSS text is not reproduced here under the Council's
  licence; the maps give requirement numbers and the topic in our
  words.

## Maintenance

The catalogue is revised with every ADR that adds, changes or retires a
control, and checked in full against the tree at each release that
changes a trust boundary. A sector map is revised when its texts change
(a new RTS, an amendment, a new revision of a registry) or when a
control it cites changes meaning. The threat model
([`../security/threat_model.md`](../security/threat_model.md)) cites
the catalogue's identifiers; a retired identifier is never reused.

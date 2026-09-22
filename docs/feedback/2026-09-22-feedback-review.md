# External feedback review — 2026-09-22

Two feedback documents on the design (5 + 21 pages) were read in full as rendered images (they contain
ASCII diagrams) and dispositioned point by point. Factual claims were verified against primary sources
the same day. The originals are archived in the private planning repository.

## Document 1 — "Feedback for our work"

| Point | Disposition |
|---|---|
| ADPulse is the long-term project; the hackathon submission is an app built on top, not "build them an MVP and throw it away". | Already the design; now stated as the architecture principle. |
| The implementation timeline treated too much of ADPulse as the hackathon deadline. | Accepted. Scope split into Tier A (product slice core), Tier B (stretch), Tier C (ADPulse future). |
| Layer 1 = ADPulse Core built for the future; Layer 2 = a vertical slice: ~10–12 checks, ECC evidence, path visualization, dashboard, PDF, remediation → rescan. | Accepted verbatim. |
| Component boundary table (long-term vs slice). | Adopted into the design spec and status file. |
| Elevate "ADPulse is bigger than the hackathon" to a project principle. | Done (`CLAUDE.md`, `architecture.md`). |

## Document 2 — "Feedback for our work – some tweaks" (32 points)

| # | Claim | Disposition | Verification |
|---|---|---|---|
| 1 | Core concept solid; collector = facts, rules = judgement. | Keep. | — |
| 2 | Hackathon rules (6, 8, 15) not actually resolved → make organizer clarification a formal gate. | Accepted (Gate 0, four written questions). | — |
| 3 | Ownership wording contradictory (private vs public); DCO ≠ copyright assignment; Naif → engine, team → app. | Accepted; wording fixed; DCO described correctly in `CONTRIBUTING.md`. | — |
| 4 | ECC 2-2-3-1 is not "password standards"; ADPulse cannot establish compliance; use evidence terminology. | Accepted: control-evidence engine, statuses, limitation sentence. | **Verified** against the official NCA EN PDF: 2-2-3-1 = "Single-factor authentication based on username and password." |
| 5 | Patch management is 2-3-3-3; patch/crypto/log controls should be not-assessed in the MVP. | Accepted. | **Verified: feedback correct; our research had 2-3-3-2 (wrong).** |
| 6 | "Compliance engine" → "control-evidence engine". | Accepted. | — |
| 7 | Scope is the biggest engineering problem. | Accepted. | — |
| 8 | Three levels: Tier A core, Tier B stretch, Tier C future. | Accepted. | — |
| 9 | 12 checks at 95–100% reliability, not 28. | Accepted (12 listed in the status file). | — |
| 10 | Don't call every graph path an attack path; edges need evidence, preconditions, confidence; UI says "potential privilege-escalation path". | Accepted. | — |
| 11 | objects keyed by objectSid is wrong (GPOs, templates, trusts have none) → object_id + type + guid + nullable sid + dn. | Accepted; objectGUID is the identity. | Correct by AD schema. |
| 12 | Data minimization: detect GPP cpassword presence, never store/decrypt; handle SDDL, descriptions, credentials carefully. | Accepted as a project rule. | Consistent with Microsoft MS14-025 guidance. |
| 13 | LDAP approach sound; don't assume every SD is readable → coverage. | Keep. | SD-flags OID and encoding **verified** (MS-ADTS). Unprivileged DACL read via 0x07 is inference; confirm in lab. |
| 14 | winacl viable but pin it (0.1.9). | Accepted. | **Verified**: 0.1.9, 2024-05-06, stale vs GitHub main. |
| 15 | React 19.3 current; Node 25 EOL; Node 24 LTS. | Accepted. | **Verified**: React 19.3.0 (2026-09-09); Node 25 EOL 2026-06-01; Node 24 Active LTS → 2026-10-20, Maintenance → 2028-04-30; Node 26 Current. |
| 16 | Scoring weights arbitrary; v1 should show factors and a documented heuristic, not "74/100 objective". | Accepted (prioritization v1). | — |
| 17 | "100% precision/recall" → lab acceptance criteria; generalization evaluation later. | Accepted. | — |
| 18 | Continuous = snapshots diffed; no agent; drift script as centerpiece. | Keep. | — |
| 19 | Exact 5-minute demo sequence. | Accepted (kept in the product-slice repo). | — |
| 20 | Dashboard overbuilt → 5 pages + report action. | Accepted. | — |
| 21 | Rename "attacker-visible" → standard-user / privileged assessment with coverage counts. | Accepted. | — |
| 22 | "Five gaps no free tool fills" → "our design differentiators". | Accepted. | — |
| 23 | Pitch wording: not "EDR/AV/IPS/SIEM are reactive". | Accepted (new problem/product sentences). | — |
| 24 | AI optional; never creates findings or changes severity/score/path/compliance; Ollama default; redact before external calls. | Accepted. | — |
| 25 | Lab is strong; expected-findings.yaml as ground truth. | Keep. | — |
| 26 | Project bigger than the hackathon; separation reasonable. | Keep. | — |
| 27 | Conceptual architecture with Finding as the central object. | Adopted (`architecture.md`). | — |
| 28 | Finding model field list. | Adopted. | — |
| 29 | Build the vertical slice much earlier (Week 2). | Accepted. | — |
| 30 | P0 / P1 / P2 priority order into PROJECT-STATUS.md. | Done. | — |
| 31 | Specific corrections: "three repositories", consistent PUBLIC visibility, React 19.3, Node 24 LTS, ECC wording, attack-path wording. | Done. | — |
| 32 | Keep as-is: snapshot architecture, facts/judgement split, coverage, low-privilege collector, remediation→rescan, interactive graph (evidence-backed), bilingual, offline demo, truth table, no fake git history. | Kept. | — |
| Note | The feedback author could not read the hackathon rules PDF (image-only). | Our transcription came from rendered images of the same PDFs, so the rules stand. | Done in session. |

## Additional findings from verification

- The official ECC document uses dots for sub-controls in tables and dashes in Appendix C; a literal search
  for "2-2-3-1" in the body finds nothing.
- The official Arabic PDF has a corrupted text layer; Arabic control titles must be transcribed from
  rendered pages.
- The ECC-2:2024 English PDF was generated 2025-07-27 (posted 31/07/2025) despite the ":2024" designation.

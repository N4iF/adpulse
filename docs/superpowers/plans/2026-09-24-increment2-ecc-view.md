# Increment 2 — NCA ECC-2:2024 control view — Plan

**Goal:** the report shows, for NCA ECC-2:2024 subdomain 2-2 (Identity and Access Management), each control
2-2-3-1 … 2-2-3-5 with its official text (EN/AR), a technical-evidence status, the checks behind it and a
reason when it is not assessed. `adrules scan` prints a one-line summary. Technical evidence only, never
compliance (D13, D36).

**Why this shape:** the control view is what a governance, risk and compliance reader looks for first, and it
is derived entirely from data the engine already has — the scan's check results and each rule's
`control_mappings` — so it needs no new collection, no new dependency and no schema change.

## Design (D36)

- **Controls shown:** always all five of 2-2-3, in document order, including those no ADPulse check covers
  yet; other ECC subdomains are out of scope for now.
- **Status per control:**
  - `technical_evidence_fail` — at least one mapped check failed;
  - `technical_evidence_pass` — at least one mapped check ran and none failed (the row lists the checks, and
    says "k of n checks could not run" when some did not);
  - `not_assessed` — no mapped check ran, with the reason: no check covers the control yet (with the checks
    planned in increments 3–6), the checks could not run in this scan, or a control-specific reason.
- **2-2-3-2** (multi-factor authentication): not assessed — Active Directory alone cannot show MFA.
- **2-2-3-5** (periodic review of identities and access rights): not assessed until identity and access
  review checks exist; the scan history is shown as the dated record of periodic assessment that supports
  it. The password-policy scans alone do not review identities or access rights, so claiming a pass would
  overstate the evidence.
- **Texts:** English verbatim from the official English PDF; Arabic transcribed from the rendered official
  Arabic PDF by two independent readers and compared (`docs/research/nca-ecc-mapping.md`).

## Files

- `packages/adrules/src/adrules/ecc_2_2024.yaml` — subdomain 2-2 title and the five controls (EN/AR), planned
  checks, control-specific reasons.
- `packages/adrules/src/adrules/controls.py` — `load_controls`, `load_subdomain`, `ecc_view(results, rules)`,
  `summary(view)`; models `ControlEvidence`, `CheckRef`.
- `report.py` + `templates/report.html.j2` — section "NCA ECC-2:2024 technical evidence" between the check
  table and the findings; the history caption says it *supports* 2-2-3-5.
- `cli.py` — `adrules scan` prints `NCA ECC-2:2024 2-2-3 technical evidence: F fail, P pass, N not assessed`.
- Tests: `test_controls.py` (status rules, order, reasons, planned list shrinking as checks land, partial
  runs, checks that could not run), report and CLI tests (both languages; the report never claims
  compliance).

## Done when

pytest, ruff and mypy green; a live `adrules scan` on DC1 shows the section in both languages (the lab is in
the fixed state: 2-2-3-1 pass, the other four not assessed; from snapshot `seeded`: 2-2-3-1 fail); docs,
status and build log updated; pushed.

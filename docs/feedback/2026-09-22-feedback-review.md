# External feedback review — 2026-09-22 (technical corrections)

Two external feedback documents on the design were read in full and dispositioned point by point. This
public file keeps the technical points; project-management points live in the private planning repo.
Factual claims were verified against primary sources the same day.

| # | Claim | Disposition | Verification |
|---|---|---|---|
| 1 | Core concept solid; collector = facts, rules = judgement. | Keep. | — |
| 2 | ECC 2-2-3-1 is not "password standards"; a snapshot cannot establish compliance; use evidence terminology. | Accepted: control-evidence engine, statuses, limitation sentence. | **Verified** against the official NCA EN PDF: 2-2-3-1 = "Single-factor authentication based on username and password." |
| 3 | Patch management is 2-3-3-3; patch/crypto/log controls should be not-assessed in the first slice. | Accepted. | **Verified: feedback correct; our research had 2-3-3-2 (wrong).** |
| 4 | "Compliance engine" → "control-evidence engine". | Accepted. | — |
| 5 | Scope: build a small vertical slice first; ~12 reliable checks, not 28. | Accepted (Tier A). | — |
| 6 | Don't call every graph path an attack path; edges need evidence, preconditions, confidence. | Accepted. | — |
| 7 | Objects keyed by objectSid is wrong (GPOs, templates, trusts have none) → objectGUID identity. | Accepted. | Correct by AD schema. |
| 8 | Data minimization: detect GPP cpassword presence, never store/decrypt; handle SDDL, descriptions, credentials carefully. | Accepted as a project rule. | Consistent with Microsoft MS14-025 guidance. |
| 9 | LDAP approach sound; don't assume every SD is readable → coverage. | Keep. | SD-flags OID and encoding **verified** (MS-ADTS). Unprivileged DACL read via 0x07 is inference; confirm in lab. |
| 10 | winacl viable but pin it (0.1.9). | Accepted. | **Verified**: 0.1.9, 2024-05-06, stale vs GitHub main. |
| 11 | React 19.3 current; Node 25 EOL; Node 24 LTS. | Accepted. | **Verified**: React 19.3.0 (2026-09-09); Node 25 EOL 2026-06-01; Node 24 Active LTS → 2026-10-20, Maintenance → 2028-04-30. |
| 12 | Scoring weights arbitrary; v1 should show factors and a documented heuristic. | Accepted (prioritization v1). | — |
| 13 | "100% precision/recall" → lab acceptance criteria; generalization later. | Accepted. | — |
| 14 | Continuous = snapshots diffed; no agent. | Keep. | — |
| 15 | Rename "attacker-visible" → standard-user / privileged assessment with coverage counts. | Accepted. | — |
| 16 | "Five gaps no free tool fills" → "our design differentiators". | Accepted. | — |
| 17 | AI optional; never creates findings or changes severity/score/path/status; local default; redact before external calls. | Accepted. | — |
| 18 | Conceptual architecture with Finding as the central object; Finding field list. | Adopted (`architecture.md`). | — |
| 19 | Keep: snapshot architecture, facts/judgement split, coverage, standard-user collector, remediation→rescan, evidence-backed graph, bilingual, offline demo, truth table, genuine git history. | Kept. | — |

## Follow-up audit — 2026-09-23

A second, internal documentation audit (six onboarding perspectives, adversarially verified) found and
fixed: the catalog count (104 checks, not 79); the Finding key (`rule_id, object_id, subject_id` — ACL
findings are about an object and a trustee); the rule "rules read only derived" (they also read the parsed
security descriptor); missing coverage semantics and derived-field dictionary; Tier 0 v1 needed by
Tier A; lab prerequisites (LDAPS certificate, standard-user account, `.env`, ISO path); the lite lab does
assess certificate templates (Configuration NC lives on DC01); `uv sync` needed root dependencies to
install the workspace packages; pytest needed `--import-mode=importlib` with two `tests/` packages;
clean-baseline false positives (built-in Guest for ACC-01, krbtgt for PRV-04) now excluded by rule
definition.

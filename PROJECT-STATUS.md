# PROJECT-STATUS — ADPulse نبض

_Last updated: 2026-09-24. Update at the end of every session. Engine content only (this repo is public);
non-engine status lives in the private `adpulse-notes/STATUS.md`._

## Phase

**Phase 1 — MVP-1 first (D31).** Three password-policy checks working end to end inside the lab DC:
collect → rules → findings → HTML report → fix → rescan shows resolved. Everything else is a later,
numbered increment. Development runs inside the lab DC `DC1` in VMware (D30, D32).

## Done

- 2026-09-21/22: design approved (`docs/superpowers/specs/`); research (104-check catalog, collectors, lab,
  comparable tools, NCA ECC text verified); workspace and repos scaffolded.
- 2026-09-23: documentation audit applied; one-DC scope (D29); in-DC VMware workflow (D30).
- 2026-09-24: MVP-1 defined (D31); dependencies trimmed to pydantic, ldap3, typer, pyyaml, jinja2.
- 2026-09-24: lab built by Naif — `DC1` (corp.local) and `SRV01`, snapshot `clean`; workspace
  `C:\ADPulse\` on DC1 with `uv sync`, pytest, ruff and mypy green on Python 3.12 (D32). The MVP-1 plan
  was dry-run and reviewed against DC1 and corrected before any code (D35); no lab script changes the
  password policy (D33); an AI "explain" button is a later feature (D34).

## Next actions (in order) — plan: `docs/superpowers/plans/2026-09-24-mvp1.md`

Tags: **[agent]** = an AI session; **[Naif]** = Naif (VMware, Group Policy Management, approvals).
Read the plan's "Corrections" section first; it overrides the code blocks where they differ.

| # | Action | Who |
|---|---|---|
| 1 | MVP-1 Tasks 1–6 with the corrections: snapshot model, test builders, Finding, rule runner and PWD-01/02/04, domain-head collector, `adrules scan` with the lifecycle diff and both HTML reports — tests first; pytest, ruff and mypy green. | [agent] |
| 2 | Task 7: `lab/Setup-Lab.ps1` (reader account, LDAPS certificate, `.env`), `lab/expected-findings.yaml`, truth-table test. | [agent] |
| 3 | Task 8: run `Setup-Lab.ps1` (with Naif's OK), record `lab-default.json`, snapshot `seeded`, scan → 2 new, manual fix in the Default Domain Policy, rescan → 2 resolved, record `lab-fixed.json`. | [agent on DC1 + Naif] |
| 4 | Increments in order, each ending in a working rescan: 2 ECC control view · 3 account flags · 4 more plain-attribute checks · 5 permissions and one path · 6 SYSVOL, krbtgt age, regressed. Before increments 3–6, read the plan's "Forward compatibility" notes. | [agent] |

## Blockers / open questions

- None for MVP-1 code. Task 8 needs Naif for the setup-script approval, the `seeded` snapshot and the
  manual fix in Group Policy Management.

## Scope

**MVP-1 (now):** PWD-01 minimum password length · PWD-02 complexity · PWD-04 account lockout — all read
from the domain object as a standard user; `adrules scan` → `ScanResult` JSON + static HTML reports in
English and Arabic (printable); lifecycle new / open / resolved. Demo: the fresh domain fails PWD-01 and
PWD-04 and passes PWD-02; after the manual fix both are resolved (D33).

**Increments (in order, each small and demo-worthy):** 2 ECC control view · 3 account flags (ACC-01,
KRB-02) · 4 plain-attribute checks (KRB-03, ACC-04, DEL-05, DEL-01) · 5 permissions and one potential
privilege-escalation path (ACL-01, ACL-03, PRV-04) · 6 SYSVOL (GPO-01), krbtgt age (KRB-01), regressed.
Increments 1–6 together are the October ceiling (the former "Tier A").

**Later (after the Cyberthon):** the rest of the 104-check catalog, AD CS, more collectors, scheduling,
integrations, AI enrichment including the per-finding "explain" button (D34).

## Risks

- MVP-1 slips → nothing else starts until it works end to end.
- Public repo → no business, strategy or personal content here; review `git diff --staged` before every push.
- The demo must run offline on the laptop (copy of the VMware lab).
- Password or lockout settings changed on the domain object instead of the Default Domain Policy revert
  silently (D33); every fix goes through the GPO.

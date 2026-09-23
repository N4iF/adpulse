# PROJECT-STATUS — ADPulse نبض

_Last updated: 2026-09-24. Update at the end of every session. Engine content only (this repo is public);
non-engine status lives in the private `adpulse-notes/STATUS.md`._

## Phase

**Phase 1 — MVP-1 first (D31).** Three password-policy checks working end to end inside the lab DC:
collect → rules → findings → HTML report → fix → rescan shows resolved. Everything else is a later,
numbered increment. Development runs inside the lab DC in VMware (D30).

## Done

- 2026-09-21/22: design approved (`docs/superpowers/specs/`); research (104-check catalog, collectors, lab,
  comparable tools, NCA ECC text verified); workspace and repos scaffolded.
- 2026-09-23: documentation audit applied; one-DC scope (D29); in-DC VMware workflow (D30).
- 2026-09-24: MVP-1 defined (D31); dependencies trimmed to pydantic, ldap3, typer, pyyaml, jinja2.

## Next actions (in order) — plan: `docs/superpowers/plans/2026-09-24-mvp1.md`

Tags: **[agent]** = an AI session; **[Naif, admin]** = Naif, elevated prompt or VMware.

| # | Action | Who |
|---|---|---|
| 1 | VMware: `DC01` + `SRV01`, dev tools and Claude Code on DC01, clone to `C:\ADPulse\` (`docs/SETUP.md`); snapshot `clean`. | [Naif, admin] |
| 2 | First session inside DC01: fill in "Lab inventory" in `lab/README.md`; `uv sync`; `uv run pytest`. | [agent on DC01] |
| 3 | MVP-1 plan tasks 1–6: snapshot model, Finding, rule runner, PWD-01/02/04, domain-head collector, `adrules scan` with the HTML report and the two-scan diff — tests first. | [agent] |
| 4 | Lab: `lab/Set-WeakPasswordPolicy.ps1` and `lab/Fix-PasswordPolicy.ps1`; first scan shows 3 findings, fix, rescan shows 3 resolved. Naif takes snapshot `seeded`. | [agent on DC01 + Naif] |
| 5 | Increments in order, each ending in a working rescan: 2 ECC control view · 3 account flags · 4 more plain-attribute checks · 5 permissions and one path · 6 SYSVOL, krbtgt age, regressed. | [agent] |

## Blockers / open questions

- Lab being set up by Naif in VMware (D30).
- The Default Domain Policy can re-apply its own password settings; on the first DC session, confirm the
  weak values hold for ten minutes (`lab/README.md` → MVP-1 lab).

## Scope

**MVP-1 (now):** PWD-01 minimum password length · PWD-02 complexity · PWD-04 account lockout — all read
from the domain object as a standard user; `adrules scan` → `ScanResult` JSON + static HTML report (EN/AR,
printable); lifecycle new / open / resolved.

**Increments (in order, each small and demo-worthy):** 2 ECC control view · 3 account flags (ACC-01,
KRB-02) · 4 plain-attribute checks (KRB-03, ACC-04, DEL-05, DEL-01) · 5 permissions and one potential
privilege-escalation path (ACL-01, ACL-03, PRV-04) · 6 SYSVOL (GPO-01), krbtgt age (KRB-01), regressed.
Increments 1–6 together are the October ceiling (the former "Tier A").

**Later (after the Cyberthon):** the rest of the 104-check catalog, AD CS, more collectors, scheduling,
integrations, AI enrichment.

## Risks

- MVP-1 slips → nothing else starts until it works end to end.
- Public repo → no business, strategy or personal content here; review `git diff --staged` before every push.
- The demo must run offline on the laptop (copy of the VMware lab).

# PROJECT-STATUS — ADPulse نبض

_Last updated: 2026-09-25. Update at the end of every session. Engine content only (this repo is public);
non-engine status lives in the private `adpulse-notes/STATUS.md`._

## Phase

**Phase 1 — MVP-1 and increments 2–3 done (2026-09-25); next: increment 4.** Five checks work end to end
inside the lab DC (collect → rules → findings → HTML reports → fix → rescan shows resolved): three on the
password policy and two on user accounts, each account named with a ready-to-paste fix command. The lab is
a small organization with seeded weaknesses (snapshot `seeded`); the report leads with what to fix and
shows the NCA ECC-2:2024 2-2-3 view on demand. Everything else arrives as numbered increments. Development
runs inside the lab DC `DC1` in VMware (D30, D32).

## Done

- 2026-09-21/22: design approved (`docs/superpowers/specs/`); research (104-check catalog, collectors, lab,
  comparable tools, NCA ECC text verified); workspace and repos scaffolded.
- 2026-09-23: documentation audit applied; one-DC scope (D29); in-DC VMware workflow (D30).
- 2026-09-24: MVP-1 defined (D31); dependencies trimmed to pydantic, ldap3, typer, pyyaml, jinja2.
- 2026-09-24: lab built by Naif — `DC1` (corp.local) and `SRV01`, snapshot `clean`; workspace
  `C:\ADPulse\` on DC1 with `uv sync`, pytest, ruff and mypy green on Python 3.12 (D32). The MVP-1 plan
  was dry-run and reviewed against DC1 and corrected before any code (D35); no lab script changes the
  password policy (D33); an AI "explain" button is a later feature (D34).
- 2026-09-24: MVP-1 Tasks 1–7 built test-first and pushed: snapshot model, test builders, Finding, rule
  runner (coverage, privilege and not-assessed gates) with PWD-01/02/04, domain-head collector over
  LDAPS, `adrules scan` (lifecycle diff, EN and AR reports), `lab/Setup-Lab.ps1` and the ground truth.
  60 tests pass (2 truth-table tests skip until the lab fixtures exist); ruff and mypy strict clean.
  Verified offline end to end from saved snapshots (2 new → 2 resolved; both reports checked in Edge).
- 2026-09-24: **MVP-1 done in the lab (Task 8).** `Setup-Lab.ps1` created `adpulse.reader` and LDAPS
  (no NTDS restart); snapshot `seeded` taken; live scan as the reader over validated LDAPS: 2 failed,
  new 2 (1.4 s); Naif fixed the Default Domain Policy by hand (14 / on / 5, 15 min); rescan: 0 failed,
  resolved 2. Fixtures `lab-default.json` and `lab-fixed.json` recorded; truth table green; 62 tests
  pass, ruff and mypy clean.
- 2026-09-24: **Increment 2 — ECC control view (D36).** The report shows the five controls of 2-2-3 with
  the official EN/AR text (Arabic transcribed twice independently from the rendered official PDF,
  identical; English re-verified) and a technical-evidence status; `adrules scan` prints a summary line.
  Live on DC1 (fixed state): 2-2-3-1 pass, four not assessed; from `lab-default.json`: 2-2-3-1 fail.
  Plan: `docs/superpowers/plans/2026-09-24-increment2-ecc-view.md`.
- 2026-09-25: **IT-first report (D37, Naif).** The report now leads with "What to fix" (plain cards: what
  we found, why it matters, how to fix, most severe first), then "Fixed since the last scan", all checks
  and the history; the NCA ECC view is a collapsed section opened with one click and printed in full.
- 2026-09-25: **Increment 3 code done** (plan `docs/superpowers/plans/2026-09-25-increment3-accounts.md`):
  the collector reads every user account through a paged directory source (only `sAMAccountName` and
  `userAccountControl` stored); ACC-01 (password not required) and KRB-02 (no Kerberos pre-authentication)
  report each account by name; `lab/Seed.ps1` builds the lab organization with the increment 3–4 seeds; one
  ground-truth schema for all increments. 92 tests pass (the 3 lab fixtures are re-recorded in the lab
  steps below); live read-only collection from DC1 works (4 accounts, 0.8 s). Not yet: `Seed.ps1` run,
  fixtures re-recorded.
- 2026-09-25: **Increment 3 done in the lab** (lab steps corrected first, see the plan). The report's fix
  commands name the account as a PowerShell literal (no more `<account>`), also in one left-to-right run in
  Arabic. `Seed.ps1` run on DC1 (17 users, 6 groups, `APP01`; a second run changed nothing); the old
  snapshot kept as `reader-ready`, new `seeded` taken. Live: 4 failed, new 4 (ECC 2 fail) → Naif fixed the
  Default Domain Policy and the two accounts → 0 failed, resolved 4 (ECC 2 pass). Fixtures `lab-default`
  (5 objects), `lab-seeded` and `lab-fixed` (22 each) recorded; truth table green on all three, none
  skipped; 98 tests pass, ruff and mypy clean. DC1 is left in the after-fix state.

## Next actions (in order)

Tags: **[agent]** = an AI session; **[Naif]** = Naif (VMware, Group Policy Management, approvals).

| # | Action | Who |
|---|---|---|
| 1 | Increment 4, plan first: KRB-03, ACC-04, DEL-05, DEL-01 (seeds already in the lab). The collector must read SPNs, a password indicator in descriptions (never the text), the machine account quota and computers with delegation flags; exclude krbtgt (it has an SPN) and domain controllers (trusted for delegation). Fixtures: record `lab-fixed.json` first from DC1's current after-fix state, then `lab-seeded` from `seeded` and `lab-default` from `reader-ready` (push before each revert). | [agent] |
| 2 | Increments 5–6 in order: 5 permissions and one path (redesign the path: AdminSDHolder, see `lab/README.md`) · 6 SYSVOL, krbtgt age, regressed. | [agent] |
| 3 | Rehearse the demo from `seeded` (script in the notes repo, 4 problems) and time each step. | [Naif] |

## Blockers / open questions

- None for the engine. Open: when the dashboard application (a separate repository, D7) starts relative
  to the engine increments.

## Scope

**MVP-1 (now):** PWD-01 minimum password length · PWD-02 complexity · PWD-04 account lockout — all read
from the domain object as a standard user; `adrules scan` → `ScanResult` JSON + static HTML reports in
English and Arabic (printable); lifecycle new / open / resolved. Demo: the fresh domain fails PWD-01 and
PWD-04 and passes PWD-02; after the manual fix both are resolved (D33).

**Increments (in order, each small and demo-worthy):** 2 ECC control view (done) · 3 account flags (ACC-01,
KRB-02; done) · 4 plain-attribute checks (KRB-03, ACC-04, DEL-05, DEL-01) · 5 permissions and one potential
privilege-escalation path (ACL-01, ACL-03, PRV-04) · 6 SYSVOL (GPO-01), krbtgt age (KRB-01), regressed.
Increments 1–6 together are the October ceiling (the former "Tier A").

**Later:** a more polished look for the report and the dashboard application (Naif, 2026-09-24). After the
Cyberthon: the rest of the 104-check catalog, AD CS, more collectors, scheduling, integrations, AI
enrichment including the per-finding "explain" button (D34).

## Risks

- MVP-1 slips → nothing else starts until it works end to end.
- Public repo → no business, strategy or personal content here; review `git diff --staged` before every push.
- The demo must run offline on the laptop (copy of the VMware lab).
- Password or lockout settings changed on the domain object instead of the Default Domain Policy revert
  silently (D33); every fix goes through the GPO.

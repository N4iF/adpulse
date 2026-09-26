# BUILD-LOG — ADPulse نبض

Dated record of what was built when. Append an entry at the end of every session. Newest at the bottom.
This log, together with the git history, is the honest timeline of the project.

## 2026-09-21

- Brainstormed the concept and the constraints of a first product slice (a university hackathon entry
  in Oct 2026).
- Research: 104-check AD security catalog; collectors (ldap3 / winacl / impacket / PowerShell / SharpHound /
  ADRecon / PingCastle XML), lab tooling (AutomatedLab, BadBlood, vulnerable-AD, GOAD, Ludus), comparable
  tools, NCA ECC-2:2024 controls.

## 2026-09-22

- Reviewed two external feedback documents (26 pages) point by point; verified their factual claims
  against primary sources (NCA ECC PDF, react.dev, nodejs.org, PyPI, MS-ADTS). See `docs/feedback/`.
- Design approved. Decisions recorded in `DECISIONS.md`.
- Scaffolded the workspace `E:\Projects\ADPulse\` and this repository: tracking files, package skeletons
  (`adsnap`, `adrules`), docs, research, spec. No engine code yet beyond `__init__` version strings.

## 2026-09-23

- Documentation audit (six onboarding perspectives, adversarially verified). Applied: check count 104;
  Finding key with `subject_id`; derived-field dictionary and coverage semantics in `architecture.md`;
  Tier 0 v1; lab prerequisites and designed path in `lab/README.md`; root `dependencies` so `uv sync`
  installs both packages; pytest `--import-mode=importlib`; `uv.lock` committed; project-management
  content moved to the private repo. Still no engine code; next is the snapshot schema (tests first).
- Scope cut (D29): no AD CS in Phase 1; PWD-01 replaces PKI-01; one-DC lab. Phase 1 implementation plan
  written (`docs/superpowers/plans/2026-09-23-phase1-engine.md`, 18 tasks, test-first).
- Working model changed (D30): the lab moves to VMware (`DC01` + `SRV01`) and development moves inside
  DC01 — Claude Code in PowerShell from a git clone at `C:\ADPulse\`. Rewrote `docs/SETUP.md` for Windows
  Server 2022 (no winget; official installers), added "Where this session runs" to `CLAUDE.md`, snapshot
  discipline to `lab/README.md` and `docs/HANDOFF.md`.

## 2026-09-24

- MVP-1 first (D31): a small supervisor panel (three Opus reviewers, one Sonnet consistency check, one
  synthesizer) reviewed all docs against the MVP-first, in-DC approach. Outcome: MVP-1 = PWD-01/02/04 on
  the domain object, `adrules scan` → `ScanResult` + static EN/AR HTML report, new/open/resolved diff with
  a "not re-assessed" guard; everything else becomes increments 2–6.
- Dependencies trimmed: winacl, smbprotocol, networkx removed; jinja2 added; `uv.lock` regenerated.
- New plan `docs/superpowers/plans/2026-09-24-mvp1.md` (9 tasks); the full-scope plan is now reference
  only. Architecture, spec, status, lab README and contribution docs aligned; lab scripts for MVP-1 do not
  force a group-policy refresh (it could re-apply the Default Domain Policy's values).
- First session inside the lab DC (`DC1`, built today by Naif; snapshot `clean` taken). Workspace
  `C:\ADPulse\` with `adpulse\` and `adpulse-notes\`; `uv sync` on Python 3.12.0, pytest (no tests yet),
  ruff and mypy green. DC time moved to internet NTP. Lab inventory recorded (D32).
- Verified the MVP-1 plan before coding: a dry run of all its code in a scratch copy (27 tests pass, but
  ruff and mypy fail as written) and reviews of the collector, the lab scripts and the docs against DC1,
  each finding checked by a second reviewer. Found: DER certificate file unusable by Python, `dc01` does
  not resolve, `Read-Host` cannot run non-interactively, `adsnap collect` exits 2, missing attributes
  become FAILs, the not-re-assessed guard lasts one scan, the printed report hides evidence and the ECC
  limitation sentence, and the Default Domain Policy re-applies password settings written to the domain
  object (every 16 h, on `gpupdate /force`, after GPO changes). Corrections added to the plan (D35).
- Naif's decisions: no lab script changes the password policy — the demo starts from the fresh domain and
  the fix is made by hand in the Default Domain Policy (D33); an AI "explain" button is a later feature
  (D34). Docs aligned (spec, catalog, architecture, SETUP, CONTRIBUTING, package READMEs, lab README).
- MVP-1 Tasks 1–7 built test-first, one commit per task: model, builders, Finding, runner with
  `NotAssessed` and the privilege gate, PWD-01/02/04 (remediation through the Default Domain Policy;
  PingCastle cross-reference `A-MinPwdLen` verified), collector (missing attributes → `None` + partial
  coverage; PEM or DER CA; robust `.env`), `adrules scan` (guard across many failed scans, previous scan
  of the same domain, duplicate scans refused, EN and AR reports with check table, coverage line and
  visible evidence and limitation, RTL isolation of Latin text), `adrules evaluate --out`, and
  `lab/Setup-Lab.ps1` (generated reader password → `.env`, Schannel-CSP LDAPS certificate, no NTDS
  restart, PEM export). A three-lens code review (correctness, runtime/packaging, rules/Arabic) found 11
  issues, all fixed with tests; a test-name collision between the two `tests` packages had hidden the
  adrules CLI tests (files renamed, rule added to CONTRIBUTING). 60 passed, 2 skipped; ruff and mypy
  clean. Not yet run against the real DC: Task 8 (`Setup-Lab.ps1`) waits for Naif's OK.
- **MVP-1 done in the lab (Task 8).** `Setup-Lab.ps1` (after a fix to its git-ignore check, which stopped it
  before any change) created `adpulse.reader` (Domain Users only) and a Schannel-CSP LDAPS certificate,
  loaded with `renewServerCertificate` — NTDS was not restarted. First collection as the reader over
  validated LDAPS: 0.9 s, GUID and SID match `Get-ADDomain`, 7 / on / 0 → `lab-default.json`. Naif took
  snapshot `seeded`. Live scan: 2 failed, new 2. Naif fixed the Default Domain Policy in Group Policy
  Management (14 / on / 5, 15 minutes) and ran `gpupdate /force`; the GPO and the domain object agree.
  Rescan: 0 failed, resolved 2 → `lab-fixed.json`. Truth table green; 62 tests pass; ruff and mypy clean.
- **Increment 2 — NCA ECC-2:2024 control view (D36).** `adrules.controls` + `ecc_2_2024.yaml`: the five
  controls of 2-2-3 with a technical-evidence status (fail / pass / not assessed with reason and planned
  checks), a report section in both languages and a summary line in `adrules scan`. The Arabic texts of
  subdomain 2-2 and 2-2-3-1…5 were transcribed from the rendered official PDF (page 19, printed ١٦) by two
  independent readers — identical — and the English re-verified against the English PDF: no difference;
  `nca-ecc-mapping.md` now records the verified Arabic. Design choice: 2-2-3-5 stays not assessed (the
  password-policy scans do not review identities); the history caption now says it *supports* 2-2-3-5.
  A one-reviewer check found no overclaiming and four latent edge cases in `ecc_view` (duplicate mapping,
  missing result, a control-specific reason being masked, unknown control ids) — all fixed with tests.
  Live on DC1 (fixed state): `0 fail, 1 pass, 4 not assessed`; from `lab-default.json`: `1 fail`.

## 2026-09-25

- **IT-first report (D37).** Naif: the control view read as noise as a first screen; most users are IT
  administrators. The template now leads with tiles (problems to fix, fixed since the last scan, checks
  passed, not checked) and "What to fix" cards (what we found, why it matters, how to fix, a small
  details line with the check id, NCA ECC control and ATT&CK), most severe first; then "Fixed since the
  last scan", all checks and the history; the NCA ECC view moved into a collapsed `<details>` that prints
  in full (`::details-content` in the print stylesheet; checked with Edge print-to-PDF). Report tests
  rewritten for the new structure; 76 tests pass. Workspace rules gained "users first", "don't follow the
  plan blindly" and "the repo is the memory".
- **Increment 3 (code).** Plan written first. `adsnap`: `DirectorySource` with paged `search()` (scope limited
  to base/subtree; ldap3 responses → rows with referrals skipped), the collector reads the domain object and
  every user account (a failed user query → partial coverage, never an abort), `derive_user` (enabled,
  built-in, password not required, no pre-authentication; unknown → None), `make_user`. `adrules`: ACC-01
  (PingCastle `S-PwdNotRequired`) and KRB-02 (`S-NoPreAuth`), both verified in the official PingCastle rule
  list; a shared `user_accounts()` makes a snapshot without users "not assessed"; cards name the account.
  `lab/Seed.ps1`: OU `Lab`, 10 staff in five department groups, helpdesk, temporary staff, four service
  accounts, `APP01`, and the increment 3–4 seeds. Finding while designing it: the planned increment-5 path
  (helpdesk → GenericWrite → svc_sql → Domain Admins) would be erased by AdminSDHolder/SDProp within an
  hour, so permission seeds wait for increment 5. `expected-findings.yaml` now has one schema for all
  increments. Two-reviewer check (engine, `Seed.ps1`): the engine reviewer ran a live collection as the
  reader and confirmed ldap3's behaviour from its source; `Seed.ps1` clean (cmdlets verified against this
  PS 5.1/WS2022 install, idempotent, no SPN collisions); two low findings fixed. 92 tests pass.
- **Increment 3 done in the lab.** A fresh-session review (six readers, each checked by a second) found
  that the lab steps would overwrite the only pre-seed snapshot, left the new fixtures uncommitted before the
  snapshot, and that the report's fix commands printed a literal `<account>`; the steps were corrected
  first. Fix commands now name the account as a PowerShell single-quoted literal (every PowerShell quote
  character doubled; a reviewer confirmed with the PowerShell 5.1 parser that a name cannot break out), and
  the Arabic report keeps such a command in one left-to-right run even for names with punctuation. On DC1:
  `lab-default.json` (5 objects) → `Seed.ps1` (17 users, 6 groups, `APP01`; a second run changed nothing;
  password policy untouched) → `lab-seeded.json` (22 objects) → Naif renamed the old snapshot to
  `reader-ready` and took a new `seeded` → live scan: 4 failed, new 4, ECC 2 fail, both account cards named
  → Naif fixed the Default Domain Policy (14 / on / 5, 15 minutes) and the two accounts in his own console
  → rescan: 0 failed, resolved 4, ECC 2 pass → `lab-fixed.json`. Truth table green on all three fixtures,
  none skipped; 98 tests pass; ruff and mypy clean. Stale docs fixed (package READMEs, the plan pointer in
  `CLAUDE.md`, the ACC-01 catalog note, lab README, SETUP, HANDOFF). DC1 left in the after-fix state.
- **Increment 4 (code).** Plan first, checked before approval by three reviewers against the code and DC1
  (read-only and `-WhatIf`): they found that `Set-ADAccountControl 'APP01'` cannot find the computer (hence
  accounts are named by sAMAccountName, `APP01$`), that a bare `pass` would flag "Pass-the-hash notes", and
  that the reference plan's DEL-05 would pass when the quota is missing. `adsnap`: the domain quota, users'
  SPNs and unconstrained delegation, password words in description/info/comment (English and Arabic, word
  boundaries; the text is read, matched and dropped), computers with `is_dc` (516/521) and delegation; a
  failed computer query is partial coverage. `adrules`: DEL-01 (users and non-DC computers, enabled or not;
  PingCastle `P-UnconstrainedDelegation`), KRB-03 (krbtgt excluded; the SPNs are the evidence), ACC-04
  (T1552), DEL-05 (`S-ADRegistration`; not assessed when the quota is unread); the truth table skips only
  clean recordings by an older collector. A three-lens code review then found five more issues, all fixed
  with tests: ACC-04's command cleared `description` whatever matched (now `-Clear <attributes>`), a missing
  computer list could hide a user DEL-01 finding (each side read separately; a pass needs both), the Arabic
  report dropped a closing `}`/`)` out of its left-to-right run, DEL-05's not-assessed reason was not
  translated, and Arabic password words needed any spacing. Live read-only check on DC1: exactly KRB-03 ×3,
  ACC-04, DEL-01 `APP01$`, DEL-05 (DC1, SRV01, krbtgt not flagged; no free text stored). 139 tests pass (3
  lab fixtures to re-record); ruff and mypy clean.

## 2026-09-26

- **Two snapshots (D38, Naif).** `lab-default.json` and the `reader-ready` snapshot are dropped: the seeded
  and after-fix recordings already hold every default object. The ground truth has two states; the lab keeps
  `clean` and `seeded`. Increment 4's lab steps need one revert (to `seeded`).

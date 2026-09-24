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
  No engine code yet; next is MVP-1 Task 1.

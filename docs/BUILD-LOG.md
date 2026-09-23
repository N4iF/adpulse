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

# BUILD-LOG — ADPulse نبض

Dated record of what was built when. Append an entry at the end of every session. Newest at the bottom.
This log, together with the git history, is the honest timeline of the project.

## 2026-09-21

- Brainstormed the concept and constraints for Cyberthon 2026 (KFU); read the invite poster and the
  platform pages (rules, tracks, timeline, registration form) as images.
- Research: 79-check AD security catalog; collectors (ldap3 / winacl / impacket / PowerShell / SharpHound /
  ADRecon / PingCastle XML), lab tooling (AutomatedLab, BadBlood, vulnerable-AD, GOAD, Ludus), comparable
  tools, NCA ECC-2:2024 controls.

## 2026-09-22

- Reviewed two external feedback documents (26 pages) point by point; verified their factual claims
  against primary sources (NCA ECC PDF, react.dev, nodejs.org, PyPI, MS-ADTS). See `docs/feedback/`.
- Design approved. Decisions recorded in `DECISIONS.md`.
- Scaffolded the workspace `E:\Projects\ADPulse\` and this repository: tracking files, package skeletons
  (`adsnap`, `adrules`), docs, research, spec. No engine code yet beyond `__init__` version strings.

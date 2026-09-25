# CLAUDE.md — working rules for AI-assisted sessions in `adpulse`

This is **ADPulse نبض**, Naif Al Anazi's independent open-source project (Apache-2.0, public repo).
Read this file fully before doing anything.

## Session protocol (mandatory)

1. **Start:** read `PROJECT-STATUS.md`, then the last 3 entries of `docs/BUILD-LOG.md`. Work only on the
   "Next actions" listed there unless the user says otherwise.
2. **End (or before any long pause):** update `PROJECT-STATUS.md` (phase, done, next actions, blockers),
   append a dated entry to `docs/BUILD-LOG.md`, run the tests, commit and push. Never leave uncommitted
   work at the end of a session. The repo is the shared memory across machines; assistant memory is not.
3. When switching machines, follow `docs/HANDOFF.md`.

## Where this session runs (D30)

Normally **inside the lab domain controller `DC1`** (`dc1.corp.local`, Windows Server 2022 in VMware; older
documents call it `DC01`), in PowerShell, in the workspace `C:\ADPulse\` with this repo at
`C:\ADPulse\adpulse` (D32). The same repo also works on the host PC or the laptop; check with
`hostname` and `(Get-CimInstance Win32_ComputerSystem).PartOfDomain`.

When running on DC1:
- **Lab only.** This domain is the ADPulse lab (`lab/README.md`). Never point anything at another domain.
- **Admin rights are for the lab scripts.** Change Active Directory only through the scripts in `lab/`
  (`Setup-Lab.ps1`; later `Seed.ps1`, `Fix-*.ps1`, `Drift.ps1`). Any other directory change: ask Naif
  first. Password and lockout settings are changed only in the Default Domain Policy GPO, never on the
  domain object (D33). ADPulse itself only reads.
- **The collector runs as `adpulse.reader`** (standard mode), never as the admin session, so the
  "standard-user assessment" claim stays true. Privileged mode is a separate, explicit run.
- **Snapshots revert the clone.** Commit and push before asking Naif to revert a VMware snapshot; after a
  revert, `git pull` every repo first. You cannot revert your own VM.
- **Shell is Windows PowerShell 5.1:** no `&&`/`||` (use `;` and `if ($?) { … }`); quote paths with spaces.
- First session on a new DC: fill in "Lab inventory" in `lab/README.md` from `Get-ADDomain`,
  `Get-ADDomainController` and `Get-ADComputer -Filter *`, then commit (done for DC1 on 2026-09-24).

## Non-negotiable rules

- **No `Co-Authored-By` trailers** in commits, ever. Conventional commit messages (`feat:`, `fix:`,
  `docs:`, `test:`, `chore:`, `lab:`).
- **Genuine git history.** Real dates. No backdating, no re-committing old work to look new.
- **This repo is public.** No business plans, vision, pricing, strategy, correspondence, personal data,
  credentials or real domain data. Those live in the private `adpulse-notes` repo. About the hackathon
  product slice, only neutral facts belong here (that a first slice targets it, the Tier A scope, dates
  of engineering milestones); never organizer rules or their interpretation, organizer questions or
  answers, team composition, registration logistics, risks or tactics.
- **Never scan a real domain.** Lab (`corp.local` in VMware) only.
- **Keep it simple, MVP first.** The smallest slice that works end to end comes first (MVP-1, D31);
  everything else is a later increment. No extra VMs, services, libraries or ceremony before an
  increment needs them.
- **Data minimization:** store evidence needed to explain a finding, never secrets unnecessary to explain
  it (no GPP password values, no decrypted secrets, redact password-like strings, no credentials in fixtures).
- **Terminology:** "ECC technical evidence / alignment" (never "ECC compliance" or "compliance score");
  "potential privilege-escalation path" (never bare "attack path"); "standard-user assessment /
  privileged assessment" (never "attacker-visible").
- **Determinism:** rules are deterministic; any AI feature is enrichment only and never creates a finding
  or changes severity, priority, paths or control status.

## Architecture principle

ADPulse Core is built for correctness, extensibility and long-term use. Product slices (like the Cyberthon
app, in a separate repo) build only enough surface to demonstrate the core. Cutting scope means cutting the
product slice, never shrinking the core's quality.

Finding is the central domain object: `Collector → Snapshot → {Rule Engine, Evidence Normalizer} →
Finding → {Controls Mapping, Path Graph, Lifecycle} → applications`. Collectors produce facts; rules judge.
Rules never read `raw`; they read `derived` fields and the parsed `security_descriptor` only
(dictionary in `docs/architecture.md`).

## Engineering conventions

- Python 3.12, `uv` workspace (`pyproject.toml` at root, packages under `packages/`).
- TDD: write the failing test first (pytest). Every rule ships with positive and negative mini-snapshot
  tests. Graph edges ship with precondition tests.
- Lint/format with `ruff`. Type hints everywhere; pydantic v2 models.
- Object identity is `object_id` = objectGUID (every AD object has one); `object_sid` is nullable.
- A rule's `evaluate(snapshot, meta, ctx)` returns `list[Finding]` (one per failure on one object); the
  runner wraps it in a `CheckResult` (D31). Finding key is
  `(rule_id, object_id, subject_id)`; `subject_id` is the trustee for ACL checks, else null.
- Tests: `uv run pytest` runs with `--import-mode=importlib` (two `tests/` packages). Also
  `uv run ruff check`. Rule files are `pwd_01.yaml` + `pwd_01.py` (importable names, no hyphens).
- When an increment adds a library (e.g. `winacl` in increment 5), pin it and test what we rely on.
- Docs: design specs under `docs/superpowers/specs/`, implementation plans under `docs/superpowers/plans/`.

## Where things live

| Need | Path |
|------|------|
| Current state and next actions | `PROJECT-STATUS.md` |
| Decision log | `DECISIONS.md` |
| What was built when | `docs/BUILD-LOG.md` |
| Setup on a new machine | `docs/SETUP.md` |
| Design spec | `docs/superpowers/specs/2026-09-22-adpulse-design.md` |
| **Plan being executed** (finished plans stay as reference: MVP-1 with its "Corrections", increment 2) | `docs/superpowers/plans/2026-09-25-increment3-accounts.md` |
| Reference plan for later increments (not plug-in; see the MVP-1 plan's forward-compatibility notes) | `docs/superpowers/plans/2026-09-23-phase1-engine.md` |
| Check catalog (104 checks) and the twelve of increments 1–6 (former Tier A) | `docs/research/ad-check-catalog.md` |
| Lab contract, prerequisites, designed path | `lab/README.md` |
| Collector/lab/tooling research | `docs/research/stack-and-lab.md` |
| Comparable tools | `docs/research/comparable-tools.md` |
| NCA ECC mapping (verified text) | `docs/research/nca-ecc-mapping.md` |
| External feedback and verification | `docs/feedback/` |

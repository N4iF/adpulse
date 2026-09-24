# ADPulse نبض

**Continuous Active Directory security control assessment.**
ADPulse turns Active Directory state into security-control evidence and remediation priorities, continuously.

> Security teams invest heavily in runtime detection and response, but identity and configuration
> weaknesses can persist underneath those controls and need separate posture assessment.

Status: **pre-alpha — MVP-1 works end to end in the lab** (September 2026).

## What works today (MVP-1, 2026-09-24)

On the lab domain controller, as an ordinary domain user over LDAPS:

```powershell
uv run adrules scan   # collect → 3 checks → compare with the previous scan → reports in English and Arabic
```

- **Checks:** PWD-01 minimum password length, PWD-02 password complexity, PWD-04 account lockout (the
  domain password policy).
- **Output:** `snapshots/<id>.scan.json` and a printable HTML report per language: check status, evidence,
  remediation, NCA ECC-2:2024 technical evidence (2-2-3-1) with its assessment-limitation sentence, and
  the scan history.
- **Lifecycle:** findings are new / open / resolved between scans; a check that could not run never shows
  "resolved".
- **Verified in the lab:** fresh domain → 2 findings; fix in the Default Domain Policy → the rescan shows
  both resolved (recorded fixtures and a truth-table test in the repo).

## What it is designed to do

Only the MVP-1 part above exists today; the bullets below describe the design, which arrives in
increments (`PROJECT-STATUS.md`).

```
AD facts  →  security checks  →  evidence  →  control mapping  →  assessment status
                                                   ↓
                        remediation  →  re-scan  →  new / resolved / regressed
```

- **Agentless, standard-user collection.** A snapshot of the domain is taken over LDAPS with an ordinary
  domain account (plus SYSVOL over SMB). What could not be collected is reported as coverage, never
  silently passed.
- **Deterministic checks with evidence.** Every finding carries the objects affected, the evidence that
  proves it, a plain-language sentence for management, a remediation, MITRE ATT&CK techniques and control
  mappings.
- **Control evidence, not compliance claims.** Findings are mapped to NCA ECC-2:2024 controls as
  *technical evidence* with explicit `not_assessed` states and an assessment-limitation statement.
- **Potential privilege-escalation paths.** An evidence-backed graph (membership, ACL rights, delegation,
  certificate enrollment) with preconditions and confidence on every edge.
- **Continuous by design.** Snapshots are diffed; findings have a lifecycle (new, open, resolved, regressed).
- **Arabic and English.** Rule texts are bilingual from day one.

## Packages

| Package | Purpose |
|---------|---------|
| `packages/adsnap` | Collector and the versioned snapshot schema. Collectors produce facts. |
| `packages/adrules` | Check catalog, Finding model, prioritization, path graph, Tier 0 logic, control-evidence engine. The engine judges. |

Applications (dashboards, reports, APIs) are built on top of these packages in separate repositories.

## Layout

```
packages/adsnap/    collector + schema
packages/adrules/   catalog, finding, prioritize, graph, tier0, controls
lab/                lab contract and scripts (VMware test domain; sessions run inside its DC)
docs/               architecture, setup, handoff, build log, research, specs
```

## Start here

1. `PROJECT-STATUS.md` — phase, next actions, scope (MVP-1 first: three password-policy checks end to end).
2. `docs/architecture.md` — snapshot, Finding, coverage, Tier 0, the derived-field dictionary.
3. `docs/research/ad-check-catalog.md` — the long-term catalog and the 12 Tier A checks.
4. `CONTRIBUTING.md` — how to add a check, tests first.

## Development

Python 3.12, managed with `uv`. See `docs/SETUP.md`. Tests use pytest and are written first.

```bash
uv sync            # installs adsnap and adrules editable, plus dev tools
uv run pytest      # exit code 5 ("no tests collected") until the first test exists
uv run ruff check
```

## Safety

ADPulse is an assessment tool. Never run the collector against a domain you are not authorized to assess.
The project ships with scripts to build an isolated lab domain for development and demos.

## License

Apache License 2.0. Copyright 2026 Naif Al Anazi. See `LICENSE`, `NOTICE` and `CONTRIBUTING.md`.

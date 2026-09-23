# ADPulse نبض

**Continuous Active Directory security control assessment.**
ADPulse turns Active Directory state into security-control evidence and remediation priorities, continuously.

> Security teams invest heavily in runtime detection and response, but identity and configuration
> weaknesses can persist underneath those controls and need separate posture assessment.

Status: **pre-alpha, design complete, engine under construction** (September 2026).

## What it is designed to do

The packages are skeletons today; the bullets below describe the design, and `PROJECT-STATUS.md` shows
what exists.

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
lab/                generic Hyper-V lab builders (deliberately misconfigured test domain)
docs/               architecture, setup, handoff, build log, research, specs
```

## Start here

1. `PROJECT-STATUS.md` — phase, next actions, scope boundary.
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

# adrules

Checks, Finding model, prioritization, potential privilege-escalation path graph, Tier 0 logic and the
control-evidence engine. Part of the ADPulse نبض engine. Depends on `adsnap` models.

**The engine judges. It reads only `derived` snapshot fields.**

## Modules (planned)

| Module | Purpose |
|--------|---------|
| `catalog/` | One YAML (metadata, bilingual texts, mappings) + one Python `evaluate(snapshot)` per check. |
| `finding/` | The Finding model — the central domain object. Key = (rule_id, object_id). |
| `prioritize/` | Documented factor model + labelled heuristic priority score. |
| `graph/` | Evidence-backed graph; edges carry evidence, preconditions and confidence. |
| `tier0/` | Tier 0 seed list and closure. |
| `controls/` | Control-evidence engine: NCA ECC-2:2024 controls → technical evidence status + limitations. |

## CLI (planned)

```bash
adrules evaluate snapshot.json --out findings.json
adrules paths snapshot.json --from "CORP\\helpdesk" --to tier0
```

## Status

Skeleton only. Finding model and the first three checks (DEL-01, KRB-03, ACL-01) come first, tests first.

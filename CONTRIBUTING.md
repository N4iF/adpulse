# Contributing to ADPulse نبض

Thank you for considering a contribution. ADPulse is maintained by Naif Al Anazi and licensed under the
Apache License 2.0.

## Licensing of contributions

By submitting a contribution you agree that it is licensed under the Apache License 2.0, the same license
as the project. You keep the copyright to your contribution. This project uses the **Developer Certificate
of Origin (DCO)**: sign off each commit with `git commit -s`, which adds

```
Signed-off-by: Your Name <you@example.com>
```

and certifies that you wrote the change or otherwise have the right to submit it under the project
license. A DCO sign-off is a certification of origin; it is **not** a copyright assignment.

## Ground rules

- Never include data from a real Active Directory domain (fixtures come from the lab domain or are
  synthetic). Never include credentials, password values or decrypted secrets, even in tests.
- Tests first. Every rule ships with positive and negative snapshot fixtures. Every graph edge type ships
  with precondition tests.
- Rules never read `raw`; they read `derived` fields and the parsed `security_descriptor` only
  (`docs/architecture.md` lists the derived fields).
- Keep terminology: "technical evidence", "potential privilege-escalation path", "standard-user assessment".
- Bilingual texts: every user-facing rule string (`title`, `why_it_matters`, `remediation`) is an
  `{en, ar}` object in the rule YAML.
- Conventional commit messages. No `Co-Authored-By` trailers.

## Development setup

See `docs/SETUP.md`. In short: Python 3.12, `uv sync`, `uv run pytest` (runs with
`--import-mode=importlib`), `uv run ruff check`, `uv run mypy` (strict). All three must pass.

## Adding a check

1. Pick the id from `docs/research/ad-check-catalog.md` (or propose a new one in the same format).
2. Add `packages/adrules/src/adrules/catalog/<id_snake>.yaml` (e.g. `del_01.yaml`: metadata, bilingual
   texts, mappings, `requires_coverage`) and `<id_snake>.py` with `evaluate(snapshot, meta, ctx) -> list[Finding]`
   (a status plus one `Finding` per failing object, or per object/trustee pair for ACL checks).
3. Add tests under `packages/adrules/tests/` (one file per check, or one file for a closely related
   group such as `test_password_rules.py`) with a failing and a passing mini-snapshot built with
   `adsnap.testing.make_snapshot`. A rule that lacks the data it needs raises `NotAssessed(reason)`;
   missing data never becomes a FAIL or a PASS.
4. If the check needs new derived fields, add them to `adsnap` (dictionary in `docs/architecture.md`)
   with a schema version bump and tests.
5. State the required collection privilege and the coverage key the check depends on; when that
   coverage is `none`, the check must return `not_assessed`, never `pass`.

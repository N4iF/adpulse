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
- Rules read only `derived` snapshot fields, never raw LDAP attribute names.
- Keep terminology: "technical evidence", "potential privilege-escalation path", "standard-user assessment".
- Bilingual texts: every user-facing rule string has `_en` and `_ar` variants.
- Conventional commit messages. No `Co-Authored-By` trailers.

## Development setup

See `docs/SETUP.md`. In short: Python 3.12, `uv sync`, `uv run pytest`, `uv run ruff check`.

## Adding a check

1. Pick the id from `docs/research/ad-check-catalog.md` (or propose a new one in the same format).
2. Add `packages/adrules/src/adrules/catalog/<ID>.yaml` (metadata, bilingual texts, mappings) and
   `<ID>.py` with `evaluate(snapshot) -> list[Finding]`.
3. Add `tests/catalog/test_<ID>.py` with a failing and a passing mini-snapshot.
4. If the check needs new collector fields, add them to `adsnap` with a schema version bump and tests.
5. Document the required collection privilege and the coverage key the check depends on.

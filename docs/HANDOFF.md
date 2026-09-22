# HANDOFF — switching machines or ending a session

The repositories are the only shared memory between the desktop, the laptop, any VM, and any AI session.
Follow this checklist every time you stop.

## Before you stop (5 minutes)

1. Run the tests: `uv run pytest` — note failures honestly in the status file.
2. Update `PROJECT-STATUS.md`:
   - **Phase** and **Done** (what actually landed)
   - **Next actions** (numbered, specific, the first one startable without thinking)
   - **Blockers / open questions**
3. Append to `docs/BUILD-LOG.md` (date, what was built, what was verified, what was left half-done).
4. Commit with a conventional message and push:
   ```bash
   git add -A && git commit -m "docs: session handoff 2026-09-30" && git push
   ```
   Never leave uncommitted work. Never add a `Co-Authored-By` trailer.
5. If the lab changed: create a Hyper-V checkpoint and name it in the build log.

## When you arrive (2 minutes)

1. `git pull` in every repo in the workspace.
2. Read `PROJECT-STATUS.md`, then the last 3 entries of `docs/BUILD-LOG.md`.
3. `uv sync` if `pyproject.toml` or `uv.lock` changed.
4. Start with "Next actions" item 1.

## Handoff note template (paste into the status file if the stop is abrupt)

```
### Handoff 2026-MM-DD HH:MM (machine: desktop|laptop)
Where I stopped: <file/function/test>
State: <tests green? lab checkpoint name?>
Next step: <one concrete step>
Watch out: <gotcha>
```

# HANDOFF — switching machines or ending a session

The repositories are the only shared memory between the desktop, the laptop, any VM and any AI session.
Assistant memory is disposable; the repos are the truth. Follow this checklist every time you stop.

## Before you stop (5 minutes)

1. Run the checks and note failures honestly in the status file:
   ```bash
   uv run pytest && uv run ruff check
   ```
   (exit code 5 = no tests collected yet; that is fine until the first test exists.)
2. Update `PROJECT-STATUS.md` (engine content only): **Phase**, **Done**, **Next actions** (numbered,
   specific, the first one startable without thinking), **Blockers**. If non-engine work changed
   (registration, team, pitch), update `adpulse-notes/STATUS.md` instead.
3. Append to `docs/BUILD-LOG.md`: date, what was built, what was verified, what was left half-done.
4. Review the staged diff before committing — this repo is public:
   ```bash
   git add -A && git diff --staged --stat && git diff --staged
   ```
   Then commit with a conventional message and push. Do this in **every repo with changes**
   (`adpulse`, `adpulse-notes`, later the product-slice repo). Never leave uncommitted work.
   Never add a `Co-Authored-By` trailer.
5. If the lab changed: ask Naif to take a VMware snapshot and name it in the build log. Everything must be
   pushed first — a snapshot revert rolls back the clone on DC01.

## When you arrive (2 minutes)

1. `git pull` in every repo in the workspace (always, and especially after a snapshot revert).
2. Read `PROJECT-STATUS.md`, then the last 3 entries of `docs/BUILD-LOG.md`. If `adpulse-notes` is
   present, read its `STATUS.md` too.
3. `uv sync` if `pyproject.toml` or `uv.lock` changed.
4. Start with "Next actions" item 1 that matches your tag ([agent] or [Naif, admin]).

## Two people, one branch

Commit small and often to `main`; `git pull --rebase` before every push; never force-push; if a change
is large or touches shared files (schema, Finding model), open a short-lived branch and a pull request so
the other person can read it first.

## Handoff note template (paste into the status file if the stop is abrupt)

```
### Handoff <YYYY-MM-DD HH:MM> (machine: desktop|laptop)
Where I stopped: <file/function/test>
State: <tests green? lab checkpoint name?>
Next step: <one concrete step>
Watch out: <gotcha>
```

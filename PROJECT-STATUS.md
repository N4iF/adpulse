# PROJECT-STATUS — ADPulse نبض

_Last updated: 2026-09-23. Update at the end of every session. Engine content only (this repo is public);
non-engine status lives in the private `adpulse-notes/STATUS.md`._

## Phase

**Phase 1 — engine + lab.** The engine (this repo) and the Hyper-V lab are being built now. A first
product slice (dashboard, report, API) will be built on the engine in a separate repository from
15 Oct 2026; until then, application work exists only as documents.

## Done

- 2026-09-21/22: design approved (`docs/superpowers/specs/`); research: 104-check AD catalog, collectors,
  lab tooling, comparable tools, NCA ECC control text verified against the official PDF; external
  technical feedback reviewed (`docs/feedback/`); workspace and repos scaffolded.
- 2026-09-23: documentation audit applied (Finding key, derived-field dictionary, coverage semantics,
  Tier 0 v1, lab prerequisites, `uv` workspace fix, check count corrected to 104).

## Next actions (in order)

Tags: **[agent]** = an AI session can do it on any machine; **[Naif, admin]** = needs Naif and an
elevated prompt / downloads.

| # | Action | Who |
|---|---|---|
| 1 | `uv sync` (installs both packages editable), commit `uv.lock`; `uv run pytest` exits 5 ("no tests collected") until the first test exists — that is expected; `uv run ruff check`. | [agent] |
| 2 | Freeze `adsnap.model` (Snapshot, objects[] with `raw`/`derived`/`security_descriptor`, coverage, errors) and a `make_snapshot()` test builder — tests first. See `docs/architecture.md` → Derived-field dictionary. | [agent] |
| 3 | Freeze `adrules.finding` (Finding, CheckResult; key = rule_id, object_id, subject_id) — tests first. | [agent] |
| 4 | Install Node 24 LTS (Node 25 is EOL); download Windows Server 2022 + Win11 Enterprise evaluation ISOs into `lab/LabSources/ISOs/`; build the lab with `lab/01-Build-Lab.ps1` → checkpoint `clean`; create the standard-user account `adpulse.reader`; enable LDAPS (see `lab/README.md` → Prerequisites). | [Naif, admin] |
| 5 | Collector against DC01 as `adpulse.reader`: users, computers, groups, domain head, GPOs (+SYSVOL GPP files), certificate templates/CAs; security descriptors via SD-flags control 0x07; `coverage` and `errors` recorded. Fixture recorded from the lab (sanitized). | [agent after 4] |
| 6 | First 3 rules with tests: DEL-01, KRB-03, ACL-01. `adrules evaluate snapshot.json` prints findings JSON. This is the engine vertical slice. | [agent] |
| 7 | Remaining 9 Tier A rules; evidence-backed graph with the designed path; controls-evidence module (ECC 2-2-3-x); `lab/expected-findings.yaml` truth table passing. | [agent + Naif for lab seeding] |

## Blockers / open questions

- Lab not built yet (needs ISOs and admin rights on the desktop).
- `impacket` is quarantined by Windows Defender on install; replaced by `smbprotocol` (D28). If any
  future dependency trips Defender, prefer replacing it over adding an exclusion.
- Unprivileged DACL read via SD-flags 0x07 is an inference from MS-ADTS; confirm empirically in step 5.

## Scope boundary (verbatim from the approved design)

**Tier A — first product slice (P0):** connect to AD (standard user) · collect snapshot · run 12 reliable
checks · produce evidence · map selected findings to ECC (technical evidence) · show findings · show a
derived potential privilege-escalation path · generate EN/AR report · rescan after remediation · show
resolved/regressed state.

**12 Tier A checks:** DEL-01, DEL-05, ACL-01, ACL-03, PRV-04, KRB-01, KRB-02, KRB-03, PKI-01, GPO-01,
ACC-01, ACC-04 (7 Critical, 5 High). Detection details: `docs/research/ad-check-catalog.md` → "Tier A".

**Tier B — stretch (P1):** PWD-01/02/04, PRV-01/02/06, ACC-09, STL-01/02, OS-01 (finding only), Tier 0
closure via control rights, more ADCS/GPO, Arabic/RTL polishing, trend visualizations, remediation
scripts, demo automation, basic scheduler.

**Tier C — ADPulse future (P2):** the full 104-check catalog and beyond, multiple collectors, advanced
ADCS, cross-domain/multi-forest, continuous scheduling, integrations, AI enrichment, historical
analytics, category-scoring research, enterprise auth/RBAC, distributed deployment.

## Risks

- Vertical slice slips → cut Tier A checks, never add Tier B.
- Public repo → no business, strategy or personal content here; review `git diff --staged` before every push.
- `winacl` is stale (0.1.9, May 2024) → pinned; test the structures we depend on.
- Demo must run offline on the laptop (lite lab = DC01 only).

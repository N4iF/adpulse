# PROJECT-STATUS — ADPulse نبض

_Last updated: 2026-09-22 by Naif + assistant. Update at the end of every session._

## Phase

**Phase 0 → 1.** Registration package for Cyberthon 2026 is being prepared in `adpulse-notes` (Naif submits
on the KFU platform). Engine work (this repo) and the Hyper-V lab start now and continue while waiting for
the organizers' acceptance (announced 15 Oct 2026). The Cyberthon app repo (`cyberthon-adpulse`) is created
only on acceptance.

## Done

- 2026-09-21/22: design brainstormed and approved; research on AD checks (79), collectors, lab tooling,
  comparable tools and NCA ECC; two external feedback documents reviewed point by point and their factual
  claims verified (see `docs/feedback/`). Workspace and repos scaffolded.

## Next actions (in order)

1. Install Node 24 LTS (Node 25 is EOL); confirm `uv`, Python 3.12.
2. Download Windows Server 2022 evaluation ISO (+ Win11 Enterprise eval) and build the lab
   (`lab/01-Build-Lab.ps1` via AutomatedLab) → checkpoint `clean`.
3. Freeze the snapshot schema (`adsnap.model`) and the Finding model (`adrules.finding`) — tests first.
4. Collector against DC01 as a standard user: users, groups, computers, domain policy, security descriptors
   (SD flags control 0x07), SYSVOL GPP files. Record `coverage` and `errors`.
5. First 3 rules with tests: DEL-01 (unconstrained delegation), KRB-03 (kerberoastable users),
   ACL-01 (DCSync rights). CLI prints findings JSON. This is the engine vertical slice.
6. Remaining 9 MVP rules, evidence-backed graph with one designed path, controls-evidence module with the
   verified ECC 2-2-3-x text, `lab/expected-findings.yaml` truth table.

## Blockers / open questions

- Gate 0 (organizer clarification of rules 6, 8, 15) sent with the registration; answers pending.
- Team is 2 of the required 3–4 members.

## Scope boundary (verbatim from the approved plan)

**Tier A — Cyberthon core (P0):** connect to AD (standard user) · collect snapshot · run 12 reliable
checks · produce evidence · map selected findings to ECC (evidence) · show findings · show a derived
potential privilege-escalation path · generate EN/AR report · rescan after remediation · show
resolved/regressed state.

**12 MVP checks:** DEL-01, DEL-05, ACL-01, ACL-03, PRV-04, KRB-01, KRB-02, KRB-03, PKI-01, GPO-01,
ACC-01, ACC-04.

**Tier B — Cyberthon stretch (P1):** PWD-01/02/04, PRV-01/02/06, ACC-09, STL-01/02, OS-01 (finding only),
Tier 0 closure, more ADCS/GPO, Arabic/RTL polishing, better graphs, trend visualizations, remediation
scripts, demo automation, basic scheduler.

**Tier C — ADPulse future (P2):** 79+ checks, multiple collectors, advanced ADCS, cross-domain/multi-forest,
continuous scheduling, external integrations, AI enrichment, historical analytics, category scoring
research, enterprise auth/RBAC, distributed deployment.

## Risks

- Gate 0 answers unfavourable → engine work is still ADPulse; the submission strategy adapts before 20 Oct.
- Vertical slice slips → cut Tier A checks, never add Tier B.
- Public repo → no business content here; review before every push.
- `winacl` is stale (0.1.9, May 2024) → pin and test.
- Demo must run offline (laptop lite lab).

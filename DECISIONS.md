# DECISIONS — ADPulse نبض

Dated decision log. Newest at the bottom. Each entry: decision, why, consequences.

## 2026-09-21

- **D1 Product thesis.** Security teams invest heavily in runtime detection and response, but identity and
  configuration weaknesses can persist underneath those controls and need separate posture assessment.
  ADPulse continuously turns AD state into security-control evidence and remediation priorities.
- **D2 Stack.** Python 3.12 engine (ldap3, winacl, impacket, pydantic v2, networkx), FastAPI + React for
  applications. Why: team skills, best AD tooling ecosystem in Python, web dashboards demo well.
- **D3 Architecture.** Snapshot pipeline + deterministic rules + evidence-backed path graph. Not graph-first
  (Neo4j) and not an agent. Why: testable offline with fixtures, replayable, honest about coverage.
- **D4 Lab.** Local Hyper-V lab (`corp.local`), never a real domain. Built from scripts, checkpointed.
- **D5 Bilingual.** English and Arabic rule texts from day one; RTL-capable UIs.
- **D6 Frameworks.** NCA ECC-2:2024 (as technical evidence) + MITRE ATT&CK technique ids.

## 2026-09-22

- **D7 Repository structure.** ADPulse is Naif's independent open-source project (this repo, Apache-2.0,
  public). Product slices (dashboards, reports, APIs, event demos) live in separate repositories and
  depend on the engine as an open-source dependency. Why: the engine is a reusable library; slices come
  and go. Consequence: nothing in this repo is specific to one slice; no business content here.
- **D8 License.** Apache-2.0, a standard open-source licence, so any product slice or third party can
  consume the engine under well-understood terms. DCO sign-off for contributors is not copyright
  assignment; contributions are Apache-2.0-licensed by their authors.
- **D9 Genuine history.** Real commit dates only; no backdating or staged re-commits.
- **D10 Core vs product-slice principle.** Build the core for correctness, extensibility and long-term
  use; build product slices only as much as needed to demonstrate it. Scope cuts hit the slice.
- **D11 Finding-centric model.** Finding is the central domain object with evidence, evidence_source,
  why_it_matters, remediation, privilege_required, exposure, blast_radius, control_mappings,
  attack_techniques, related_paths, lifecycle timestamps, confidence, assessment_limitations.
- **D12 Object identity.** `object_id` = objectGUID (present on every AD object); `object_sid` nullable
  (GPOs, certificate templates, trusts, OUs have none). Finding key = (rule_id, object_id).
- **D13 ECC evidence model.** Map findings to NCA ECC-2:2024 controls as *technical evidence* with
  statuses technical_evidence_pass / technical_evidence_fail / not_assessed (+reason) and a fixed
  assessment-limitation sentence. Never "compliance" or a compliance score. MVP maps only subdomain 2-2
  (2-2-3-1 … 2-2-3-5, verified verbatim from the official NCA English PDF). Patch management is 2-3-3-3.
- **D14 Path terminology.** "Potential privilege-escalation path"; every edge has evidence, preconditions
  and confidence. Never claim exploitation.
- **D15 Assessment modes.** "Standard-user assessment" vs "privileged assessment", with coverage shown as
  "N of M checks; K need elevated privileges".
- **D16 Prioritization v1.** Documented factors (severity, exposure, affected assets, privilege required,
  blast radius, evidence confidence, path relevance) + a labelled heuristic priority score. No 0–100 domain
  score presented as objective measurement; category scoring is future research.
- **D17 Data minimization.** Store evidence needed to explain a finding, never secrets unnecessary to
  explain it.
- **D18 Continuous = periodic snapshots diffed** (new / open / resolved / regressed), not a resident agent.
- **D19 AI.** Enrichment only, optional, provider-swappable (Ollama default; external providers opt-in
  with redaction). Never creates findings or changes severity, priority, paths or control status.
- **D20 Versions (verified 2026-09-22).** Python 3.12; Node 24 LTS (Node 25 is EOL); React 19.3;
  `winacl` pinned (0.1.9 on PyPI, stale) with structure tests.

## 2026-09-23 (documentation audit)

- **D21 Snapshot shape.** One `objects[]` list for every AD object type (domain head, GPOs, templates,
  CAs, trusts, FGPPs included); no separate policy/PKI/trust sections. Rules never read `raw`; they read
  `derived` and the parsed `security_descriptor`. The derived-field dictionary in `architecture.md` is
  the contract between collector and rules.
- **D22 Finding key.** `(rule_id, object_id, subject_id)`; a rule returns a `CheckResult` (status +
  findings). Why: ACL findings are about an object *and* a trustee.
- **D23 Coverage semantics.** Keys `directory_objects, acls, gpo_settings, gpo_files, adcs, ca_registry,
  dc_os_config`; values `full | partial | none`; rules declare `requires_coverage`; `none` → `not_assessed`.
- **D24 Tier 0 v1 in Tier A.** Well-known groups by RID + recursive membership + DCs + RID 500/502. The
  control-rights closure stays Tier B.
- **D25 Lite lab.** DC01 exported from the seeded full lab keeps the Configuration NC, so template-based
  checks (PKI-01) are assessable on the laptop; CA-host checks are not.
- **D26 Tooling fixes.** Root `dependencies = ["adsnap", "adrules"]` so `uv sync` installs the workspace
  packages; pytest `--import-mode=importlib`; `uv.lock` committed; rule files use snake_case names.
- **D27 Catalog count.** The research catalog holds 104 checks (90 standard-user, 10 elevated, 4 mixed),
  not 79 as first stated.
- **D30 Work inside the lab DC, on VMware (Naif, 2026-09-23).** The lab runs in VMware Workstation: `DC01`
  (domain controller) and `SRV01` (member server, the real target of the DEL-01 seed). Claude Code runs in
  PowerShell inside DC01 from a git clone at `C:\ADPulse\`; code, tests, collector and lab scripts run
  there. Supersedes the Hyper-V lab and "develop on the host" parts of D14/D29. Why: working inside the
  environment being assessed removes guesswork. Consequences: snapshot reverts roll back the clone (push
  before every revert, pull after); the collector still runs as `adpulse.reader`; directory changes only
  through `lab/` scripts.
- **D29 Scope cut (Naif, 2026-09-23): no AD CS in Phase 1.** PKI-01 moves to Tier B; PWD-01 (weak
  minimum password length) is the twelfth Tier A check. The lab is a single DC (`DC01`) installed by hand
  once, then scripted (`Install-DC.ps1`, `Seed.ps1`); LDAPS uses a self-signed certificate on DC01; no
  AutomatedLab, BadBlood, vulnerable-AD, SRV01 or WS01 in Phase 1. Why: one of twelve checks does not
  justify a second VM, a CA and template seeding; "build the right project, not a complicated one".
- **D28 SMB library.** `smbprotocol` instead of `impacket` for SYSVOL reads. Why: Windows Defender
  quarantines impacket's DCOM module on install (os error 225), and impacket is an offensive toolkit we
  only needed for file reads; `smbprotocol` is pure Python, maintained, supports NTLM/Kerberos, and is not
  flagged. Security-descriptor parsing stays with `winacl`.

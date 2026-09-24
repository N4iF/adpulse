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
- **D28 SMB library.** `smbprotocol` instead of `impacket` for SYSVOL reads. Why: Windows Defender
  quarantines impacket's DCOM module on install (os error 225), and impacket is an offensive toolkit we
  only needed for file reads; `smbprotocol` is pure Python, maintained, supports NTLM/Kerberos, and is not
  flagged. Security-descriptor parsing stays with `winacl`.
- **D29 Scope cut (Naif, 2026-09-23): no AD CS in Phase 1.** PKI-01 moves to Tier B; PWD-01 (weak
  minimum password length) is the twelfth Tier A check. The lab is a single DC (`DC01`) installed by hand
  once, then scripted (`Install-DC.ps1`, `Seed.ps1`); LDAPS uses a self-signed certificate on DC01; no
  AutomatedLab, BadBlood, vulnerable-AD, SRV01 or WS01 in Phase 1. Why: one of twelve checks does not
  justify a second VM, a CA and template seeding; "build the right project, not a complicated one".
- **D30 Work inside the lab DC, on VMware (Naif, 2026-09-23).** The lab runs in VMware Workstation: `DC01`
  (domain controller) and `SRV01` (member server, the real target of the DEL-01 seed). Claude Code runs in
  PowerShell inside DC01 from a git clone at `C:\ADPulse\`; code, tests, collector and lab scripts run
  there. Supersedes the Hyper-V lab and "develop on the host" parts of D4/D29. Why: working inside the
  environment being assessed removes guesswork. Consequences: snapshot reverts roll back the clone (push
  before every revert, pull after); the collector still runs as `adpulse.reader`; directory changes only
  through `lab/` scripts.

## 2026-09-24

- **D31 MVP-1 first (Naif).** Build the smallest slice that works end to end before anything else: three
  password-policy checks on the domain head (PWD-01 minimum length, PWD-02 complexity, PWD-04 lockout),
  read as a standard user over LDAPS; `adrules scan` writes a `ScanResult` JSON and a static HTML report
  (printable, EN/AR, no JavaScript framework); lifecycle new / open / resolved between two scans. Every
  other check arrives as a numbered increment that ends in a working rescan. `winacl`, `smbprotocol` and
  `networkx` leave the dependencies until the increment that needs them; `jinja2` is the only addition.
  Rule contract everywhere: `evaluate(snapshot, meta, ctx) -> list[Finding]`; the runner wraps findings
  in a `CheckResult`. Why: a judge must see a working result early; heavy features up front delay that.
  Plan: `docs/superpowers/plans/2026-09-24-mvp1.md`.
- **D32 The lab as built (Naif, 2026-09-24).** The DC is `DC1` (`dc1.corp.local`, 192.168.50.10), not
  `DC01`; the second machine `SRV01` (192.168.50.210) is a domain-joined Windows 10 client, not a server.
  The workspace on DC1 is `C:\ADPulse\` holding the repos `adpulse\` and `adpulse-notes\` (as in
  `docs/SETUP.md`); D30's "clone at `C:\ADPulse\`" means that workspace. DC1 takes its time from internet
  NTP, because the VM clock had already jumped once and scan order depends on `collected_at`. Why: record
  reality instead of the plan's names. Consequences: `.env` and docs use `dc1.corp.local`; inventory in
  `lab/README.md`.
- **D33 ADPulse only reads; no lab script sets the password policy (Naif, 2026-09-24).** The MVP-1 demo
  starts from the fresh domain (fails PWD-01 and PWD-04, passes PWD-02) and the fix is made by hand in the
  Default Domain Policy with Group Policy Management, followed by `gpupdate /force` and a rescan that
  shows both resolved. `Set-WeakPasswordPolicy.ps1` and `Fix-PasswordPolicy.ps1` are dropped; the only
  MVP-1 lab script is `Setup-Lab.ps1` (the `adpulse.reader` account and the LDAPS certificate). Why:
  verified on DC1 that the Default Domain Policy re-applies its account-policy values (every 16 hours, on
  `gpupdate /force`, after GPO changes), so values written to the domain object by a script can silently
  revert and show a false "resolved"; scripting the GPO instead is extra work the demo does not need,
  and the manual GPO fix is the real-world remediation. Consequences: the demo shows 2 findings and
  1 pass, then 2 resolved; any later seed or fix of password or lockout settings goes through the GPO.
- **D34 AI "explain" button later (Naif, 2026-09-24).** A later, optional per-finding action that explains
  the finding and proposes fix steps and references, as a starting point for the administrator. It is
  D19 enrichment: it never creates findings or changes severity, status or evidence, and it is not part
  of MVP-1. Each rule's static bilingual remediation stays the baseline.
- **D35 MVP-1 plan corrected before execution (2026-09-24).** The MVP-1 plan was dry-run in a scratch copy
  and reviewed against DC1; its design holds (27 tests pass) but several steps could not work as
  written (DER certificate file, `dc01` host name, interactive password prompt, `adsnap collect`
  command, lint and type gates) and some behaviour contradicted the project's own rules (missing data
  becoming a FAIL, the "not re-assessed" guard lasting one scan, the printed report hiding evidence and
  the ECC limitation sentence). The corrections are listed at the top of the plan and are part of the
  MVP-1 work; forward-compatibility gaps with the reference plan are recorded there for increments 3–6.

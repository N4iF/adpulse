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

- **D7 Ownership structure.** ADPulse is Naif's independent open-source project (this repo, Apache-2.0,
  public). Product slices such as the Cyberthon 2026 submission live in separate repositories and depend on
  the engine as an open-source dependency. Why: Cyberthon rule 15 assigns the submitted project to the
  organizer; rule 8 allows disclosed open-source libraries. Consequence: nothing in this repo may be
  specific to a submission; no business content here.
- **D8 License.** Apache-2.0 (true open source), not a non-commercial licence. Why: rule 8 says
  "open-source"; a withheld proprietary core would risk exclusion. DCO sign-off for contributors is not
  copyright assignment; contributions are Apache-2.0-licensed by their authors.
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

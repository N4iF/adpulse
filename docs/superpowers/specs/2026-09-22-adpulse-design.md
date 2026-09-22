# ADPulse نبض — design specification

Date: 2026-09-22 · Status: approved · Owner: Naif Al Anazi

## 1. Purpose

ADPulse continuously turns Active Directory (AD) state into security-control evidence and remediation
priorities. Security teams invest heavily in runtime detection and response, but identity and configuration
weaknesses can persist underneath those controls and need separate posture assessment.

ADPulse is an independent open-source project (Apache-2.0). Product slices — dashboards, reports, APIs,
hackathon applications — are built on top of it in separate repositories and depend on the engine as an
open-source dependency.

## 2. Architecture principle

> ADPulse Core: build for correctness, extensibility and long-term use.
> Product slices: build only enough integration and product surface to demonstrate the core convincingly.

Cutting scope always cuts the slice, never the core's quality.

| Component | ADPulse long-term | First product slice |
|-----------|-------------------|---------------------|
| AD collector | Architecture + reusable package | Working subset |
| Rules | Extensible catalog (79+) | 12 lab-verified rules |
| Graph | General engine | Selected evidence-backed paths |
| Control evidence | Mapping framework | Selected IAM controls |
| Dashboard | Future product architecture | 5 key pages |
| AI | Provider abstraction | Optional demo |
| Lab | Reusable lab tooling | One polished scenario |
| Reports | Reusable report engine | One polished EN/AR report |
| Scheduler | Future | Optional/basic |

## 3. Pipeline

```
AD facts → security checks → evidence → control mapping → assessment status
                                            ↓
                remediation → re-scan → new / open / resolved / regressed
```

Conceptual architecture: `Collector → Snapshot → {Rule Engine, Evidence Normalizer} → Finding →
{Controls Mapping, Path Graph, Lifecycle} → applications`. Finding is the central domain object. See
`docs/architecture.md` for the data shapes.

## 4. Components

### 4.1 adsnap — collector and snapshot schema

- LDAPS with paged search; NTLM bind as an ordinary domain account (standard-user assessment) or an
  elevated account (privileged assessment). Security descriptors read with `LDAP_SERVER_SD_FLAGS`
  (OID 1.2.840.113556.1.4.801, flags 0x07) and parsed with `winacl` (pinned) into a canonical rights
  vocabulary. Extended-right and attribute GUIDs resolved from `CN=Extended-Rights` and the schema.
- SYSVOL over SMB (impacket) for Group Policy Preference files and `GptTmpl.inf`.
- Output: versioned `Snapshot` (pydantic v2). Object identity = objectGUID; `object_sid` nullable.
  `raw` LDAP attributes vs `derived` normalized fields; rules read only `derived`.
- `coverage` per area (`full | partial | none`) and `errors[]`; per-module failures never abort a run.
- Data minimization: presence of GPP `cpassword` recorded, value never stored or decrypted; password-like
  strings in descriptions reduced to a match indicator; no credentials in snapshots or fixtures.
- Interfaces: `adsnap collect …`, `adsnap collect --from-fixture …`. Additional adapters (PingCastle XML,
  SharpHound JSON) are future importers producing the same schema.

### 4.2 adrules — checks, findings, prioritization, graph, controls

- **Catalog:** one YAML per check (id, category, severity, privilege_required, title_en/ar,
  why_it_matters_en/ar, remediation_en/ar, control_mappings.nca_ecc_2_2024[], attack_techniques[],
  matches_pingcastle_rule, evidence_source) and one `evaluate(snapshot) -> list[Finding]`. Statuses:
  `fail | pass | not_assessed | needs_elevated`. The long-term catalog is `docs/research/ad-check-catalog.md`.
- **Finding model:** id, rule_id, title, category, severity, status, affected_object,
  affected_object_type, evidence, evidence_source, why_it_matters, remediation, privilege_required,
  exposure, blast_radius, control_mappings, attack_techniques, related_paths, first_seen, last_seen,
  resolved_at, confidence, assessment_limitations. Key = (rule_id, object_id).
- **Prioritization v1:** documented factors (severity, exposure, affected assets, privilege required,
  blast radius, evidence confidence, path relevance) and a labelled heuristic priority score. No domain
  score is presented as an objective measurement.
- **Graph:** networkx; nodes = objects; edges = MemberOf, GenericAll, GenericWrite, WriteDacl, WriteOwner,
  DCSync, ForceChangePassword, WriteProperty(KeyCredentialLink | servicePrincipalName | member),
  AllowedToDelegate, RBCD, GPO-link, ESC-enroll; every edge `{type, source, target, evidence,
  preconditions[], confidence}`. Output: "potential privilege-escalation paths" to Tier 0 as JSON subgraphs.
- **Tier 0:** seed list (see catalog) and transitive closure over membership and control rights.
- **Controls:** control-evidence engine for NCA ECC-2:2024 (verified text in
  `docs/research/nca-ecc-mapping.md`): per control `technical_evidence_pass | technical_evidence_fail |
  not_assessed (+reason)`, evidence list, and the fixed limitation sentence. Never "compliance".

### 4.3 Product-slice application (separate repository)

FastAPI + SQLite (SQLModel) storage of scans, gzip snapshots and findings with lifecycle; React 19.3 +
Vite + TypeScript on Node 24 LTS; five pages (Overview, Findings, Potential privilege-escalation paths,
Controls/Evidence, Scan/History) plus a report action; Jinja2 bilingual HTML → PDF via Playwright. Depends
on `adsnap` and `adrules` via editable installs in development and pinned tags in releases.

### 4.4 AI (future, optional)

Enrichment only: finding evidence → plain-language explanation → management summary. Never creates a
finding or changes severity, priority, paths or control status. Ollama default; external providers
explicit opt-in; names, UPNs, hostnames, domains, SIDs and internal paths redacted before anything leaves
the machine.

## 5. Lab

Hyper-V Internal switch `LABNET` 10.10.10.0/24, domain `corp.local`, Windows Server 2022 evaluation:
DC01 (AD DS, DNS), SRV01 (AD CS), optional WS01. Built and seeded from scripts (AutomatedLab, BadBlood,
vulnerable-AD, `04-Seed-Extras.ps1`) with checkpoints `clean` and `seeded`; `05-Drift.ps1` changes state
between scans; `Fix-<check>.ps1` remediations; `expected-findings.yaml` is the ground-truth dataset.
See `lab/README.md`.

## 6. Verification and validation

- Unit tests first (pytest) for every rule (positive and negative mini-snapshots), graph edge
  preconditions, collector fixtures and the `winacl` structures relied upon.
- Lab acceptance criteria: 100% detection of intentionally seeded findings; 0 unexpected findings on the
  clean baseline; every result with reproducible evidence; every remediation causing the expected lifecycle
  transition. Generalization evaluation across multiple domains/snapshots is future work.
- Standard-user proof: the collector runs as a plain domain user and reports coverage honestly.
- Performance targets: lab scan < 2 min; synthetic 10k-user snapshot < 30 s; path query < 1 s.

## 7. Error handling

Collector modules fail independently and record `errors[]` and `coverage`; rules depending on missing
data return `not_assessed`; rules needing elevated rights return `needs_elevated` in standard mode;
applications run scans as background tasks with status; any AI call times out to deterministic rule text.

## 8. Terminology (binding)

- "ECC technical evidence / alignment" — never "ECC compliance" or "compliance score".
- "Potential privilege-escalation path" — never bare "attack path"; nothing is exploited.
- "Standard-user assessment" / "privileged assessment" with coverage counts — never "attacker-visible".
- "Continuous periodic assessment" — not a resident agent.

## 9. Engineering conventions

Python 3.12, `uv` workspace, pydantic v2, ruff, mypy strict, TDD. Conventional commits, genuine history,
no `Co-Authored-By` trailers. Versions verified 2026-09-22: Node 24 LTS, React 19.3.0, winacl 0.1.9.

## 10. Roadmap tiers

- **Tier A (first slice core):** connect (standard user) · snapshot · 12 checks · evidence · ECC evidence
  for 2-2-3-x · findings view · one derived path · EN/AR report · rescan · resolved/regressed.
  Checks: DEL-01, DEL-05, ACL-01, ACL-03, PRV-04, KRB-01, KRB-02, KRB-03, PKI-01, GPO-01, ACC-01, ACC-04.
- **Tier B:** PWD-01/02/04, PRV-01/02/06, ACC-09, STL-01/02, OS-01, Tier 0 closure, more ADCS/GPO,
  RTL polishing, trend visualizations, remediation scripts, basic scheduler.
- **Tier C:** 79+ checks, multiple collectors, advanced ADCS, multi-domain/forest, continuous scheduling,
  integrations, AI enrichment, historical analytics, category-scoring research, enterprise auth, RBAC.

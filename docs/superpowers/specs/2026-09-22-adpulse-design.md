# ADPulse نبض — design specification

Date: 2026-09-22 · Status: approved · Amended 2026-09-23/24 (D21–D31) · Owner: Naif Al Anazi

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
| Rules | Extensible catalog (104 today) | 12 lab-verified rules |
| Graph | General engine | Selected evidence-backed paths |
| Control evidence | Mapping framework | Selected IAM controls |
| Dashboard | Future product architecture | 5 key pages |
| AI | Provider abstraction | Optional demo |
| Lab | Reusable lab tooling | One polished scenario |
| Reports | Reusable report engine | One polished EN/AR report |
| Scheduler | Future | Optional/basic |

### MVP-1 first (amended 2026-09-24, D31)

The first thing built and demonstrated is MVP-1: three password-policy checks (PWD-01 minimum length,
PWD-02 complexity, PWD-04 lockout) read from the domain object as a standard user, run end to end by
`adrules scan`, producing a `ScanResult` and one static HTML report (EN/AR, printable), with new / open /
resolved between scans. Everything in the table above beyond that arrives as numbered increments, each
ending in a working rescan (order in `PROJECT-STATUS.md`). No component in sections 4.1–4.4 is built
before the increment that needs it.

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
- SYSVOL over SMB (`smbprotocol`, pure Python) for Group Policy Preference files and `GptTmpl.inf`.
- Output: versioned `Snapshot` (pydantic v2): one `objects[]` list for every object type. Object identity
  = objectGUID; `object_sid` nullable. `raw` LDAP attributes vs `derived` normalized fields plus the parsed
  `security_descriptor`; rules never read `raw` (dictionary in `docs/architecture.md`).
- `coverage` per area (`full | partial | none`) and `errors[]`; per-module failures never abort a run.
- Data minimization: presence of GPP `cpassword` recorded, value never stored or decrypted; password-like
  strings in descriptions reduced to a match indicator; no credentials in snapshots or fixtures.
- Interfaces: `adsnap collect …`, `adsnap collect --from-fixture …`. Additional adapters (PingCastle XML,
  SharpHound JSON) are future importers producing the same schema.

### 4.2 adrules — checks, findings, prioritization, graph, controls

- **Catalog:** one YAML per check (id, category, severity, privilege_required, title_en/ar,
  why_it_matters_en/ar, remediation_en/ar, control_mappings.nca_ecc_2_2024[], attack_techniques[],
  matches_pingcastle_rule, evidence_source) and one `evaluate(snapshot, meta, ctx) -> list[Finding]`. Statuses:
  `fail | pass | not_assessed | needs_elevated`. The long-term catalog is `docs/research/ad-check-catalog.md`.
- **Finding model:** a rule returns `list[Finding]`; the runner wraps it in a `CheckResult` (status, reason,
  confidence, findings[]) (D31). Finding:
  id, rule_id, title, category, severity, status, affected_object, affected_object_type, subject_id,
  evidence, evidence_source, why_it_matters, remediation, privilege_required, exposure, blast_radius,
  control_mappings, attack_techniques, related_paths, first_seen, last_seen, resolved_at, confidence,
  assessment_limitations. Key = (rule_id, object_id, subject_id).
- **Prioritization v1:** documented factors (severity, exposure, affected assets, privilege required,
  blast radius, evidence confidence, path relevance) and a labelled heuristic priority score. No domain
  score is presented as an objective measurement.
- **Graph:** networkx; nodes = objects; edges = MemberOf, GenericAll, GenericWrite, WriteDacl, WriteOwner,
  DCSync, ForceChangePassword, WriteProperty(KeyCredentialLink | servicePrincipalName | member),
  AllowedToDelegate, RBCD, GPO-link, ESC-enroll; every edge `{type, source, target, evidence,
  preconditions[], confidence}`. Output: "potential privilege-escalation paths" to Tier 0 as JSON subgraphs.
- **Tier 0:** v1 (Tier A) = well-known groups by RID + recursive membership + DCs + RID 500/502;
  the control-rights closure is Tier B. Details in `docs/architecture.md`.
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

VMware Workstation, domain `corp.local`: `DC01` (Windows Server 2022, AD DS, DNS, self-signed LDAPS
certificate) and `SRV01` (member server). Development runs inside DC01 (Claude Code in PowerShell, git
clone at `C:\ADPulse\`, amended 2026-09-23, D30). `Install-DC.ps1`, `Seed.ps1` (the 12 Tier A seeds, the
designed path, the `adpulse.reader` account), snapshots `clean` and `seeded`; `Drift.ps1` changes state
between scans; `Fix-<check>.ps1` remediations; `expected-findings.yaml` is the ground-truth dataset. AD CS
and scale seeding are Tier B. See `lab/README.md`.

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
  Checks: DEL-01, DEL-05, ACL-01, ACL-03, PRV-04, KRB-01, KRB-02, KRB-03, GPO-01, ACC-01, ACC-04, PWD-01
  (amended 2026-09-23, D29: PKI-01 → Tier B; single-DC lab).
- **Tier B:** PKI-01 (AD CS), PWD-02/04, PRV-01/02/06, ACC-09, STL-01/02, OS-01, Tier 0 closure, more
  GPO checks, RTL polishing, trend visualizations, basic scheduler, lab scale and extra VMs.
- **Tier C:** the full 104-check catalog and beyond, multiple collectors, advanced ADCS,
  multi-domain/forest, continuous scheduling, integrations, AI enrichment, historical analytics,
  category-scoring research, enterprise auth, RBAC.

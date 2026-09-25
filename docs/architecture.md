# ADPulse نبض — architecture

## Principle

> ADPulse Core: build for correctness, extensibility and long-term use.
> Product slices (dashboards, reports, apps): build only enough surface to demonstrate the core.

## Conceptual architecture (Finding-centric)

```
┌───────────┐
│ Collector │  adsnap: LDAPS (paged), SD-flags control 0x07, SYSVOL over SMB (smbprotocol)
└─────┬─────┘
      ↓
┌───────────┐
│ Snapshot  │  versioned JSON: objects[] (raw / derived / security_descriptor), coverage, errors
└─────┬─────┘
      ├──────────────────────┐
      ↓                      ↓
┌─────────────┐      ┌────────────────────┐
│ Rule Engine │      │ Evidence Normalizer│
└──────┬──────┘      └─────────┬──────────┘
       └──────────┬────────────┘
                  ↓
          ┌───────────────┐
          │ Finding Model │   the central domain object, key (rule_id, object_id, subject_id)
          └───────┬───────┘
      ┌───────────┼───────────────┐
      ↓           ↓               ↓
 Controls      Path Graph      Lifecycle
 Mapping   (evidence-backed)  (new/open/resolved/regressed)
      └───────────┼───────────────┘
                  ↓
             Applications (API, dashboard, PDF, CLI)
```

**MVP-1 builds only this path (D31):** collector (domain object over LDAPS, no security descriptors, no
SYSVOL) → snapshot → rule engine (PWD-01/02/04) → Finding → lifecycle (new/open/resolved) → static
HTML reports in English and Arabic. Control mapping as a view, the path graph and the other collectors
are later increments. The Snapshot, Finding and CheckResult contracts stay the same; the test builders,
the collector's directory source and the rule context grow with increments 3–5 (see the MVP-1 plan's
forward-compatibility notes, D35). ADPulse only reads the directory.

Collectors produce facts. The engine judges. Rules never read `raw`; they read only normalized data —
`derived` fields and the parsed `security_descriptor` — so a new collector (a PingCastle XML or
SharpHound JSON importer) needs a new adapter and zero rule changes.

## Snapshot (adsnap.model)

Every AD object — users, computers, groups, OUs, the domain head, GPOs, certificate templates, CAs
(enrollment services), trusts, FGPPs — is one entry in `objects[]`. There are no separate policy/PKI/trust
sections; rules filter by `object_type` (helpers `snapshot.by_type("gpo")`, `snapshot.domain()`).
Password policy lives on the domain object; SYSVOL results live on each GPO object.

```jsonc
{
  "schema_version": "1.0",
  "snapshot": {
    "id": "2026-10-01T02:00:00Z-corp.local",
    "collected_at": "2026-10-01T02:00:00Z",
    "collector": { "name": "adsnap", "version": "0.1.0", "auth": "simple", "mode": "standard" },
    "domain": { "object_id": "…", "dn": "DC=corp,DC=local", "netbios": "CORP", "sid": "S-1-5-21-…", "functional_level": "2016" }
  },
  "objects": [{
    "object_id": "b1f3…",               // objectGUID: every AD object has one
    "object_type": "user",              // user|computer|group|ou|gpo|cert_template|ca|trust|fgpp|domain|container
    "object_sid": "S-1-5-21-…-1105",    // nullable: GPO, template, trust, OU, CA have none
    "dn": "CN=svc_sql,OU=Svc,DC=corp,DC=local",
    "raw": { "userAccountControl": 66048, "servicePrincipalName": ["MSSQLSvc/…"], "pwdLastSet": "…" },
    "derived": { "enabled": true, "spn_count": 1, "kerberoastable": true, "asrep_roastable": false,
                 "unconstrained_delegation": false, "password_age_days": 2760, "admin_count": 1 },
    "security_descriptor": { "owner_sid": "…", "dacl_protected": false,
      "aces": [{ "kind": "allow", "trustee_sid": "…", "trustee_name": "CORP\\helpdesk",
                 "rights": ["GenericWrite"], "rights_mask": 131112,
                 "object_type_guid": null, "object_type_name": null, "inherited": false }] }
  }],
  "coverage": { "directory_objects": "full", "acls": "full", "gpo_settings": "partial", "gpo_files": "full",
                "adcs": "full", "ca_registry": "none", "dc_os_config": "none" },
  "errors": [ { "stage": "ca_registry", "msg": "not collected in standard mode" } ]
}
```

**Canonical ACE rights vocabulary:** `GenericAll, GenericWrite, WriteOwner, WriteDacl, WriteProperty,
Self, AllExtendedRights, Owns, AddSelf,
ExtendedRight:DS-Replication-Get-Changes` (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2),
`ExtendedRight:DS-Replication-Get-Changes-All` (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2),
`ExtendedRight:DS-Replication-Get-Changes-In-Filtered-Set` (89e95b76-444d-4c62-991a-0facbeda640c),
`ExtendedRight:User-Force-Change-Password` (00299570-246d-11d0-a768-00aa006e0529),
`ExtendedRight:Certificate-Enrollment` (0e10c968-78fb-11d2-90d4-00c04f79dc55),
`ExtendedRight:Certificate-AutoEnrollment` (a05b8cc2-17bc-4802-a710-e7c15ab866a2),
`WriteProperty:msDS-KeyCredentialLink, WriteProperty:servicePrincipalName, WriteProperty:member`.
An object-specific ACE (with `object_type_guid`) is normalized to its scoped token, never to an unscoped
right.

### Coverage and assessment status

`coverage` keys: `directory_objects` (LDAP objects and attributes), `acls` (security descriptors),
`gpo_settings` (GPO metadata and links), `gpo_files` (SYSVOL files), `adcs` (templates and CAs in the
Configuration NC), `ca_registry` (CA host settings — privileged only), `dc_os_config` (DC registry /
services — privileged only). Values: `full`, `partial` (some objects or attributes could not be read;
details in `errors[]`), `none`.

Each rule declares `requires_coverage: [...]`. If any required key is `none`, the rule returns
`not_assessed` with the reason; if `partial`, it assesses what it has and sets `confidence: medium`.
A rule that needs privileged collection returns `needs_elevated` in standard mode. A `pass` is only ever
returned when the data needed to fail was actually collected: a rule that finds a derived field missing
(`None`) raises `NotAssessed(reason)` and the runner reports `not_assessed`; missing data never becomes a
FAIL or a PASS.

### Derived-field dictionary (Tier A)

ACL checks read `security_descriptor.aces[]`. Every other Tier A input is one of these fields.

| Field | Type | On | Source | Coverage | Used by |
|---|---|---|---|---|---|
| `enabled` | bool | user | `userAccountControl` bit 0x2 not set | directory_objects | PRV-04, KRB-02, KRB-03, ACC-01 |
| `is_dc` | bool | computer | `primaryGroupID` 516 or 521 | directory_objects | DEL-01, Tier 0 |
| `is_builtin` | bool | user | RID 500 (Administrator), 501 (Guest), 502 (krbtgt), `krbtgt_<n>` | directory_objects | PRV-04 exclusions |
| `unconstrained_delegation` | bool | user, computer | `userAccountControl` bit 0x80000 (enabled or not) | directory_objects | DEL-01 |
| `spns` | list[str] | user | the `servicePrincipalName` values, sorted ([] when none) | directory_objects | KRB-03 evidence, PRV-04 |
| `kerberoastable` | bool | user | `spns` not empty and not krbtgt (RID 502, `krbtgt_<n>`; a built-in Administrator with an SPN counts; gMSA/MSA are not `user`) | directory_objects | KRB-03, PRV-04 |
| `asrep_roastable` | bool | user | `userAccountControl` bit 0x400000 | directory_objects | KRB-02 |
| `admin_count` | int | user, group, computer | `adminCount` (0 when absent) | directory_objects | PRV-04 |
| `password_age_days` | int or null | user, computer | `collected_at` − `pwdLastSet`; null when 0 | directory_objects | KRB-01 |
| `passwd_notreqd` | bool | user | `userAccountControl` bit 0x20 | directory_objects | ACC-01 |
| `password_in_text_indicator` | bool | user | `description`/`info`/`comment` contain a password word, case-insensitive: `password`, `passwd`, `passphrase`, `pwd` as words (a letter may not touch them, a digit may), `pass:` or `pass=`, `كلمة المرور`, `كلمة مرور`, `كلمة السر`, `كلمة سر` (so not `bypass`, `passport`, `Pass-the-hash`); values never stored | directory_objects | ACC-04 |
| `password_in_text_attrs` | list[str] | user | attribute names that matched | directory_objects | ACC-04 |
| `member_of` | list[object_id] | user, group, computer | `memberOf` + the `primaryGroupID` group | directory_objects | Tier 0 |
| `machine_account_quota` | int | domain | `ms-DS-MachineAccountQuota` | directory_objects | DEL-05 |
| `min_password_length` | int | domain | `minPwdLength` | directory_objects | PWD-01 |
| `password_complexity` | bool | domain | `pwdProperties` & 0x1 | directory_objects | PWD-02 |
| `lockout_threshold` | int | domain | `lockoutThreshold` (0 = never locks) | directory_objects | PWD-04 |
| `gpo_name_guid` | str | gpo | `cn` `{…}` — the SYSVOL folder name (not the objectGUID) | directory_objects | GPO-01 |
| `gpp_cpassword_files` | list[str] | gpo | SYSVOL `Policies/{gpo_name_guid}/**/*.xml` with a non-empty `cpassword` (relative paths only) | gpo_files | GPO-01 |

Tier B (PKI-01, needs AD CS): `enrollee_supplies_subject`, `client_auth_eku`, `requires_manager_approval`,
`authorized_signatures`, `published_on_cas` on `cert_template` objects (coverage `adcs`).

### Never stored (data minimization)

`description`, `info`, `comment` values (reduced to the indicator + attribute names); GPP `cpassword`
values or decrypted secrets (only the file path is kept); LAPS passwords; any credential used by the
collector; raw SDDL except as evidence for an ACL finding. Fixtures come from the lab or are synthetic.

## Finding and CheckResult (adrules.finding)

A rule's `evaluate(snapshot, meta, ctx)` returns `list[Finding]`; the runner applies the coverage gate
and wraps the result in a `CheckResult`: `rule_id`, `status` (`fail | pass | not_assessed |
needs_elevated`), `reason`, `confidence`, `findings[]`. Each Finding is one failure on one object.

**Finding v1 (frozen for MVP-1):**

```
rule_id, category, severity
title, why_it_matters (management sentence), remediation   — each {en, ar}
affected_object (object_id), affected_object_type, affected_name
subject_id, subject_name   (trustee for ACL checks, else null)
evidence, evidence_source
control_mappings, attack_techniques, confidence
```

Lifecycle state and first/last seen live in `ScanResult`, not on the Finding. Later increments may add
optional fields (exposure, blast_radius, related_paths, priority) without breaking v1.

Finding key = `(rule_id, object_id, subject_id)`. One object drives the report, the control view, history
and, later, the app and API.

## ScanResult (adrules.scan)

What `adrules scan` writes (`snapshots/<id>.scan.json`, plus `<id>.en.html` and `<id>.ar.html`) and what
the HTML reports render:

```
schema_version
snapshot_id, collected_at, domain, mode
coverage
results: [CheckResult]
lifecycle: [{key, state: new | open | resolved, not_reassessed, finding}]
previous_scan_id
```

The previous scan is the latest saved scan of the same domain collected before this one. The diff starts
from that scan's `new` and `open` lifecycle entries (including `not_reassessed` ones). A finding is
`resolved` only when its rule was actually re-assessed (pass or fail) in the new scan; if the rule could
not run, the finding stays `open` with `not_reassessed: true` for as many scans as that lasts, so a failed
connection can never show a false "resolved".

## Rules (adrules.catalog)

One YAML per check (`del_01.yaml`: id, category, severity, privilege_required, requires_coverage,
`title`, `why_it_matters` and `remediation` each as `{en, ar}`, control_mappings.nca_ecc_2_2024[],
attack_techniques[], matches_pingcastle_rule, evidence_source, params) and one Python module
(`del_01.py`) with `evaluate(snapshot, meta, ctx) -> list[Finding]`. Thresholds (e.g. PWD-01 minimum
length, default 12) are `params` with documented defaults. Tests: positive and negative mini-snapshots
per rule.

## Prioritization (adrules.prioritize)

Version 1 exposes documented factors — severity, exposure, affected assets, privilege required, blast
radius, evidence confidence, path relevance — and a clearly labelled heuristic priority score. No domain
score is presented as an objective measurement; category scoring is future research.

## Graph (adrules.graph)

Nodes are snapshot objects. Edges: MemberOf, GenericAll, GenericWrite, WriteDacl, WriteOwner, DCSync,
ForceChangePassword, WriteProperty(KeyCredentialLink | servicePrincipalName | member), AllowedToDelegate,
RBCD, GPO-link, ESC-enroll. Every edge is `{type, source, target, evidence, preconditions[], confidence}`.
Paths to Tier 0 are "potential privilege-escalation paths"; nothing is exploited.

## Tier 0 (adrules.tier0)

**Tier 0 v1 (used by Tier A):** the domain object; the well-known groups Enterprise Admins (519), Schema
Admins (518), Domain Admins (512), Administrators (S-1-5-32-544), Account Operators (548), Backup
Operators (551), Server Operators (549), Print Operators (550), Domain Controllers (516), Read-only Domain
Controllers (521), Key Admins (526), Enterprise Key Admins (527), Group Policy Creator Owners (520), Cert
Publishers (517), and `DnsAdmins` by name; the built-in Administrator (RID 500) and krbtgt (RID 502);
computers with `is_dc`; plus recursive membership of those groups (`member_of`). Machine-resolvable from
`object_sid` and `member_of` alone.

**Tier 0 closure (Tier B):** iteratively add principals holding control rights (GenericAll, GenericWrite,
WriteDacl, WriteOwner, WriteProperty on Tier 0 attributes, AllExtendedRights, ForceChangePassword,
DCSync pair) over Tier 0 objects, until stable; any undocumented member of the closure is itself a finding.

## Control evidence (adrules.controls)

NCA ECC-2:2024 controls (official EN text; AR titles transcribed from the rendered official PDF) → per
control: `technical_evidence_pass | technical_evidence_fail | not_assessed (+reason)`, the evidence list,
and the constant limitation sentence: "This result evaluates technical AD configuration only;
organizational policy/process compliance is not assessed." ADPulse never claims compliance.

**Implemented (increment 2, D36):** subdomain 2-2, controls 2-2-3-1 … 2-2-3-5, always all five. Texts live in
`adrules/ecc_2_2024.yaml`; `adrules.controls.ecc_view(results, rules)` derives the status from the checks
whose `control_mappings.nca_ecc_2_2024` name the control — fail if one failed, pass if at least one ran and
none failed, otherwise not assessed with the reason (no check yet, with the planned checks; the checks could
not run; or a control-specific reason, e.g. 2-2-3-2 MFA). 2-2-3-5 stays not assessed until identity and
access review checks exist; the scan history is shown as the dated record that supports it. Nothing is
stored: the view is recomputed from a `ScanResult`.

## Lifecycle

Scans are diffed. A finding keyed (rule_id, object_id, subject_id) is `new` when first seen, `open`
while it persists, `resolved` when absent after being present (and its rule re-assessed). `regressed`
(it returns after being resolved) comes with increment 6. "Continuous"
means continuous periodic assessment, not a resident agent.

## Assessment modes

`standard` (ordinary domain account) and `privileged`. Applications show "Collection privileges:
standard · Coverage: N of M checks · K checks need elevated privileges".

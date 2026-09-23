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
    "collector": { "name": "adsnap", "version": "0.1.0", "auth": "ntlm", "mode": "standard" },
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
returned when the data needed to fail was actually collected.

### Derived-field dictionary (Tier A)

ACL checks read `security_descriptor.aces[]`. Every other Tier A input is one of these fields.

| Field | Type | On | Source | Coverage | Used by |
|---|---|---|---|---|---|
| `enabled` | bool | user, computer | `userAccountControl` bit 0x2 not set | directory_objects | DEL-01, PRV-04, KRB-02, KRB-03, ACC-01 |
| `is_dc` | bool | computer | `primaryGroupID` 516 or 521 | directory_objects | DEL-01, Tier 0 |
| `is_builtin` | bool | user | RID 500 (Administrator), 501 (Guest), 502 (krbtgt), `krbtgt_<n>` | directory_objects | ACC-01, PRV-04, KRB-03 exclusions |
| `unconstrained_delegation` | bool | user, computer | `userAccountControl` bit 0x80000 | directory_objects | DEL-01 |
| `spn_count` | int | user, computer | number of `servicePrincipalName` values | directory_objects | PRV-04, KRB-03 |
| `kerberoastable` | bool | user | `spn_count` > 0 and not krbtgt (gMSA/MSA are not `user`) | directory_objects | KRB-03, PRV-04 |
| `asrep_roastable` | bool | user | `userAccountControl` bit 0x400000 | directory_objects | KRB-02 |
| `admin_count` | int | user, group, computer | `adminCount` (0 when absent) | directory_objects | PRV-04 |
| `password_age_days` | int or null | user, computer | `collected_at` − `pwdLastSet`; null when 0 | directory_objects | KRB-01 |
| `passwd_notreqd` | bool | user | `userAccountControl` bit 0x20 | directory_objects | ACC-01 |
| `password_in_text_indicator` | bool | user | `description`/`info`/`comment` matched case-insensitively against `pass`, `pwd`, `كلمة المرور`, `كلمة السر`; values never stored | directory_objects | ACC-04 |
| `password_in_text_attrs` | list[str] | user | attribute names that matched | directory_objects | ACC-04 |
| `member_of` | list[object_id] | user, group, computer | `memberOf` + the `primaryGroupID` group | directory_objects | Tier 0 |
| `machine_account_quota` | int | domain | `ms-DS-MachineAccountQuota` | directory_objects | DEL-05 |
| `min_password_length` | int | domain | `minPwdLength` | directory_objects | PWD-01 |
| `gpo_name_guid` | str | gpo | `cn` `{…}` — the SYSVOL folder name (not the objectGUID) | directory_objects | GPO-01 |
| `gpp_cpassword_files` | list[str] | gpo | SYSVOL `Policies/{gpo_name_guid}/**/*.xml` with a non-empty `cpassword` (relative paths only) | gpo_files | GPO-01 |

Tier B (PKI-01, needs AD CS): `enrollee_supplies_subject`, `client_auth_eku`, `requires_manager_approval`,
`authorized_signatures`, `published_on_cas` on `cert_template` objects (coverage `adcs`).

### Never stored (data minimization)

`description`, `info`, `comment` values (reduced to the indicator + attribute names); GPP `cpassword`
values or decrypted secrets (only the file path is kept); LAPS passwords; any credential used by the
collector; raw SDDL except as evidence for an ACL finding. Fixtures come from the lab or are synthetic.

## Finding and CheckResult (adrules.finding)

A rule returns one `CheckResult`: `rule_id`, `status` (`fail | pass | not_assessed | needs_elevated`),
`reason` (for not_assessed / needs_elevated), `confidence`, and `findings[]`. Each Finding is one failure
on one object:

```
id, rule_id, title, category, severity, status
affected_object (object_id), affected_object_type, subject_id (trustee object_id for ACL checks, else null)
evidence, evidence_source
why_it_matters (management sentence), remediation
privilege_required, exposure, blast_radius
control_mappings, attack_techniques, related_paths
first_seen, last_seen, resolved_at
confidence, assessment_limitations
```

Finding key = `(rule_id, object_id, subject_id)`. ACL-01 with two trustees holding DCSync rights yields
two findings on the domain object. One object drives dashboard, PDF, control-evidence view, path graph,
history, AI explanation and API.

## Rules (adrules.catalog)

One YAML per check (`del_01.yaml`: id, category, severity, privilege_required, requires_coverage,
title_en/ar, why_it_matters_en/ar, remediation_en/ar, control_mappings.nca_ecc_2_2024[],
attack_techniques[], matches_pingcastle_rule, evidence_source) and one Python module (`del_01.py`) with
`evaluate(snapshot) -> CheckResult`. Thresholds (e.g. KRB-01 max krbtgt age, default 180 days) are
parameters with documented defaults. Tests: positive and negative mini-snapshots per rule.

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

## Lifecycle

Snapshots are diffed. A finding keyed (rule_id, object_id, subject_id) is `new` when first seen, `open`
while it persists, `resolved` when absent after being present, `regressed` when it returns. "Continuous"
means continuous periodic assessment, not a resident agent.

## Assessment modes

`standard` (ordinary domain account) and `privileged`. Applications show "Collection privileges:
standard · Coverage: N of M checks · K checks need elevated privileges".

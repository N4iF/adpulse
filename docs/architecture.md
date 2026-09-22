# ADPulse نبض — architecture

## Principle

> ADPulse Core: build for correctness, extensibility and long-term use.
> Product slices (dashboards, reports, hackathon apps): build only enough surface to demonstrate the core.

## Conceptual architecture (Finding-centric)

```
┌───────────┐
│ Collector │  adsnap: LDAPS (paged), SD-flags control 0x07, SYSVOL over SMB
└─────┬─────┘
      ↓
┌───────────┐
│ Snapshot  │  versioned JSON: objects[] (raw vs derived), policies, pki, trusts, coverage, errors
└─────┬─────┘
      ├──────────────────────┐
      ↓                      ↓
┌─────────────┐      ┌────────────────────┐
│ Rule Engine │      │ Evidence Normalizer│
└──────┬──────┘      └─────────┬──────────┘
       └──────────┬────────────┘
                  ↓
          ┌───────────────┐
          │ Finding Model │   the central domain object, key (rule_id, object_id)
          └───────┬───────┘
      ┌───────────┼───────────────┐
      ↓           ↓               ↓
 Controls      Path Graph      Lifecycle
 Mapping   (evidence-backed)  (new/open/resolved/regressed)
      └───────────┼───────────────┘
                  ↓
             Applications (API, dashboard, PDF, CLI)
```

Collectors produce facts. The engine judges. Rules read only `derived` fields of the snapshot, never raw
LDAP attribute names, so a new collector (e.g., a PingCastle XML or SharpHound JSON importer) requires a new
adapter and zero rule changes.

## Snapshot (adsnap.model)

```jsonc
{
  "schema_version": "1.0",
  "snapshot": {
    "id": "2026-10-01T02:00:00Z-corp.local",
    "collected_at": "2026-10-01T02:00:00Z",
    "collector": { "name": "adsnap", "version": "0.1.0", "auth": "ntlm", "mode": "standard" },
    "domain": { "dn": "DC=corp,DC=local", "netbios": "CORP", "sid": "S-1-5-21-…", "functional_level": "2016" }
  },
  "objects": [{
    "object_id": "b1f3…-guid",          // objectGUID: every AD object has one
    "object_type": "user",              // user|computer|group|ou|gpo|cert_template|ca|trust|fgpp|domain|container|dc
    "object_guid": "b1f3…", "object_sid": "S-1-5-21-…-1105",   // sid nullable (GPO, template, trust, OU)
    "dn": "CN=svc_sql,OU=Svc,DC=corp,DC=local",
    "raw": { "userAccountControl": 4260352, "servicePrincipalName": ["MSSQLSvc/…"], "pwdLastSet": "…" },
    "derived": { "enabled": true, "spn_count": 1, "kerberoastable": true, "asrep_roastable": false,
                 "unconstrained_delegation": false, "password_age_days": 2760, "admin_count": 1,
                 "supported_etypes": ["RC4_HMAC"] },
    "security_descriptor": { "owner_sid": "…", "dacl_protected": false,
      "aces": [{ "kind": "allow", "trustee_sid": "…", "trustee_name": "CORP\\helpdesk",
                 "rights": ["GenericWrite"], "rights_mask": 131112,
                 "object_type_guid": "3f78c3e5-…", "object_type_name": "msDS-KeyCredentialLink",
                 "inherited": false }] }
  }],
  "policies": { "password_policy": { … }, "fgpp": [ … ], "gpos": [ { "guid": "…", "links": [], "settings": {}, "sysvol_findings": [] } ] },
  "pki": { "cas": [], "templates": [] },
  "trusts": [],
  "coverage": { "acls": "full", "gpo_settings": "partial", "gpo_files": "full", "adcs": "none", "dc_os_config": "none" },
  "errors": [ { "stage": "adcs", "msg": "Configuration NC read denied" } ]
}
```

Canonical ACE rights vocabulary (≈15 tokens): `GenericAll, GenericWrite, WriteOwner, WriteDacl,
WriteProperty, Self, AllExtendedRights, Owns, ExtendedRight:DS-Replication-Get-Changes,
ExtendedRight:DS-Replication-Get-Changes-All, ExtendedRight:User-Force-Change-Password,
WriteProperty:msDS-KeyCredentialLink, WriteProperty:servicePrincipalName, WriteProperty:member, AddSelf`.

`coverage` lets a rule return `not_assessed` instead of a false pass when the collector was blind.

Data minimization: GPP `cpassword` presence is recorded (file, GPO, location) but the value is never
stored or decrypted; password-like strings in descriptions become a match indicator; credentials never
enter a snapshot.

## Finding (adrules.finding)

```
id, rule_id, title, category, severity, status (fail|pass|not_assessed|needs_elevated)
affected_object, affected_object_type
evidence, evidence_source
why_it_matters (management sentence), remediation
privilege_required, exposure, blast_radius
control_mappings, attack_techniques, related_paths
first_seen, last_seen, resolved_at
confidence, assessment_limitations
```

One object drives dashboard, PDF, control-evidence view, path graph, history, AI explanation and API.

## Rules (adrules.catalog)

One YAML per check (id, category, severity, privilege_required, title_en/ar, why_it_matters_en/ar,
remediation_en/ar, control_mappings.nca_ecc_2_2024[], attack_techniques[], matches_pingcastle_rule,
evidence_source) and one Python `evaluate(snapshot) -> list[Finding]`. Tests: positive and negative
mini-snapshots per rule.

## Prioritization (adrules.prioritize)

Version 1 exposes documented factors — severity, exposure, affected assets, privilege required, blast
radius, evidence confidence, path relevance — and a clearly labelled heuristic priority score. No domain
score is presented as an objective measurement. Category scoring (PingCastle-style max-of-categories,
Purple-Knight-style severity-weighted percentage) is a future research item.

## Graph (adrules.graph)

Nodes are snapshot objects. Edges: MemberOf, GenericAll, GenericWrite, WriteDacl, WriteOwner, DCSync,
ForceChangePassword, WriteProperty(KeyCredentialLink | servicePrincipalName | member), AllowedToDelegate,
RBCD, GPO-link, ESC-enroll. Every edge is `{type, source, target, evidence, preconditions[], confidence}`.
Paths to Tier 0 are "potential privilege-escalation paths"; nothing is exploited.

## Control evidence (adrules.controls)

NCA ECC-2:2024 controls (official EN text; AR titles transcribed from the rendered official PDF) → per
control: `technical_evidence_pass | technical_evidence_fail | not_assessed (+reason)`, the evidence list,
and the fixed limitation sentence: "This result evaluates technical AD configuration only; organizational
policy/process compliance is not assessed." ADPulse never claims compliance.

## Lifecycle

Snapshots are diffed. A finding keyed (rule_id, object_id) is `new` when first seen, `open` while it
persists, `resolved` when absent after being present, `regressed` when it returns. "Continuous" means
continuous periodic assessment, not a resident agent.

## Assessment modes

`standard` (ordinary domain account) and `privileged`. The UI shows "Collection privileges: standard ·
Coverage: N of M checks · K checks need elevated privileges".

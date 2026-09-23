# adsnap

Active Directory snapshot collector and versioned snapshot schema. Part of the ADPulse نبض engine.

**Collectors produce facts. They never judge.**

## What it will do (Phase 1)

- Connect over LDAPS with an ordinary domain account (standard-user assessment) or an elevated one
  (privileged assessment).
- Paged searches for users, computers, groups, OUs, GPOs, domain/DC objects, trusts, password policy and
  fine-grained password policies, certificate templates and CAs (Configuration NC).
- Read security descriptors with the `LDAP_SERVER_SD_FLAGS` control (OID `1.2.840.113556.1.4.801`,
  flags 0x07 = owner | group | DACL) and parse them with `winacl` into a canonical rights vocabulary.
- Read SYSVOL over SMB with `smbprotocol` (pure Python; `impacket` was dropped because Windows Defender
  flags it) for Group Policy Preference files and `GptTmpl.inf` (presence of `cpassword` is recorded; the
  value is never stored or decrypted).
- Write a `Snapshot` JSON with `schema_version`, `objects[]` (every AD object incl. the domain head,
  GPOs, certificate templates, CAs, trusts, FGPPs; identity = objectGUID; `raw` vs `derived` fields plus
  the parsed `security_descriptor`), `coverage` and `errors`. The derived-field dictionary is in
  `docs/architecture.md`.
- Connect with the DC's DNS name (e.g. `dc01.corp.local`), not its IP: LDAPS validates the hostname.

## CLI (planned)

```bash
adsnap collect --dc 10.10.10.10 --domain corp.local --user standard@corp.local --out snapshot.json
adsnap collect --from-fixture tests/fixtures/lab-seeded.json --out snapshot.json
```

## Status

Skeleton only. Schema and tests come first.

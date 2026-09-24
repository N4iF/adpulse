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
- Connect with the DC's DNS name (e.g. `dc1.corp.local`), not its IP: LDAPS validates the hostname.

MVP-1 (D31) reads only the domain object (password and lockout policy) with a simple bind over LDAPS; the
rest of the list above arrives with later increments.

## CLI (MVP-1)

```powershell
uv run adsnap collect --out snapshot.json   # connection settings come from .env (docs/SETUP.md §5)
uv run adsnap collect --out snapshot.json --insecure-lab   # lab only: skip certificate validation
```

## Status

Skeleton only; MVP-1 is being built (`docs/superpowers/plans/2026-09-24-mvp1.md`).

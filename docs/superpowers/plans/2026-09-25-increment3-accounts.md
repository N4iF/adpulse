# Increment 3 — User accounts and a realistic lab — Plan

**Goal:** ADPulse reads every user account (still as `adpulse.reader`, read-only) and reports two risky
account settings, each on the named account: **ACC-01** an enabled account that may have an empty password
(`PASSWD_NOTREQD`) and **KRB-02** an enabled account without Kerberos pre-authentication (`DONT_REQ_PREAUTH`,
its password can be guessed offline). The lab becomes a small, realistic organization so the demo shows
findings among ordinary accounts, not in an empty domain.

## Engine

- **Collector (adsnap):** the domain-only source becomes the generic directory source from the reference
  plan (Task 14), reduced to what is needed: `base_dn()` and a paged `search(base, filter, attributes, scope)`,
  simple bind over LDAPS, no security descriptors yet (increment 5). The collector reads the domain object
  (as before) and all user accounts `(&(objectCategory=person)(objectClass=user))`.
  - Stored per user (`raw`, data minimization): `sAMAccountName`, `userAccountControl` only.
  - Derived per user (`derive_user`, reference Task 11 subset): `enabled`, `is_builtin` (RID 500/501/502,
    krbtgt), `passwd_notreqd`, `asrep_roastable`.
  - A failed user query → `directory_objects` = `partial` + an entry in `errors[]`; the domain query failing
    still aborts (no snapshot).
- **Test builders:** `make_user(name, rid=…, **derived)` with safe defaults (reference Task 2 subset).
- **Rules:** `acc_01` and `krb_02` (YAML + Python, bilingual, NCA ECC 2-2-3-1 and 2-2-3-4, ATT&CK T1078.002
  and T1558.004). One finding per account. Evidence: account, setting, current, required. If the snapshot
  holds no user objects at all (e.g. an old domain-only snapshot) the rules raise `NotAssessed` — never a pass.
  ACC-01 has no exclusion beyond `enabled`: the built-in Guest carries the flag but is disabled by default; an
  enabled Guest without a required password is a real finding.
- **Report:** the card title names the object ("… · temp.intern"); "Account" joins the evidence labels. The
  ECC view picks the new checks up automatically: 2-2-3-4 gets its first evidence (KRB-02).
- **Ground truth:** `lab/expected-findings.yaml` becomes one schema for all increments — per lab state, per
  check, the objects that must be flagged. A check not implemented yet is ignored until it lands; every
  implemented check must match exactly and be assessed. This replaces the MVP-1 layout (forward-compatibility
  note in the MVP-1 plan).

## Lab (`lab/Seed.ps1`, changes AD: Naif's OK; idempotent; never touches the password policy)

Guards as in `Setup-Lab.ps1` (lab domain `corp.local`, a DC, elevated). Random passwords, never printed or
stored; nobody signs in with these accounts.

| Object | Detail |
|---|---|
| `OU=Lab` with `Staff`, `ServiceAccounts`, `Groups`, `Servers` | the organization |
| 10 staff | `it.fahad`, `it.sara`, `hr.noura`, `hr.omar`, `fin.khalid`, `fin.lama`, `sales.reem`, `sales.yousef`, `ops.maha`, `ops.turki` — one department group each |
| groups | `GRP-IT`, `GRP-HR`, `GRP-Finance`, `GRP-Sales`, `GRP-Operations`, `helpdesk` |
| `hd.user1` | member of `helpdesk` |
| service accounts | `svc_sql`, `svc_web`, `svc_backup`, `svc_legacy` |
| `temp.intern`, `contractor1` | temporary staff |
| `APP01` | computer object (no VM) |

Seeds (weaknesses) — only plain attributes now:

| Increment | Check | Seed |
|---|---|---|
| 3 | ACC-01 | `temp.intern`: password not required |
| 3 | KRB-02 | `svc_legacy`: Kerberos pre-authentication off |
| 4 | KRB-03 | SPNs on `svc_sql`, `svc_web`, `svc_backup` |
| 4 | ACC-04 | `contractor1` description mentions a password (no real password) |
| 4 | DEL-01 | `APP01` trusted for unconstrained delegation |
| 4 | DEL-05 | machine account quota left at the default 10 |

**Not seeded yet (increment 5):** the permission seeds (ACL-01, ACL-03) and PRV-04. The designed path in
`lab/README.md` (helpdesk → GenericWrite on `svc_sql` → Domain Admins) does not hold: every member of Domain
Admins is protected by AdminSDHolder, and SDProp resets its permissions about every hour, removing the
helpdesk ACE. Increment 5 redesigns the path. GPO-01 (increment 6) is also later.

## Lab steps (with Naif)

1. Code and `Seed.ps1` pushed (tests, ruff, mypy green; review).
2. Naif reverts DC1 to snapshot `seeded` (default policy, reader, LDAPS, no scans); `git pull` in both repos.
3. `adsnap collect` → `lab-default.json` (fresh domain, new collector).
4. `.\lab\Seed.ps1` (elevated) → `adsnap collect` → `lab-seeded.json`.
5. Naif retakes snapshot `seeded` (now with the organization and seeds) — the new demo starting point.
6. `adrules scan` → 4 problems to fix (PWD-01, PWD-04, ACC-01 temp.intern, KRB-02 svc_legacy).
7. Fix by hand: the password policy in the Default Domain Policy (as in MVP-1) and the two accounts with
   the commands in the report → `gpupdate /force` → `adrules scan` → 4 fixed → `lab-fixed.json`.
8. Truth table green on the three fixtures; docs, status, build log; push.

## Done when

pytest, ruff, mypy green including the truth table on `lab-default`, `lab-seeded` and `lab-fixed`; the live
scan shows the two account findings by name in both languages; pushed.

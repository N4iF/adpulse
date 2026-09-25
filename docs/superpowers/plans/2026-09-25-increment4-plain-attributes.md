# Increment 4 — Four plain-attribute checks — Plan

**Goal:** four more checks, each read from plain directory attributes as `adpulse.reader`:
- **DEL-01:** an account (not a domain controller) trusted for unconstrained delegation.
- **KRB-03:** an enabled user account with a service principal name. Its password can be guessed offline
  ("Kerberoasting").
- **ACC-04:** an account's description mentions a password.
- **DEL-05:** any user may add computers to the domain (machine account quota above 0).

The seeds are already in the lab (`Seed.ps1`, increment 3), so no lab script changes. The demo shows 10
problems, fixes 6 live and keeps 4 honestly "still open" (Naif, 2026-09-25: option b). The plan was checked
before approval by three reviewers (engine, lab, rules), with live read-only and `-WhatIf` tests on DC1; their
corrections are included.

## Choices (facts verified 2026-09-25; say if any should change)

- **Demo fixes**, besides the four of increment 3: **DEL-01** (`APP01$`, the only Critical card, one
  command) and **DEL-05** (one command; ECC 2-2-3-3 turns to pass). Still open:
  - **KRB-03 ×3:** the real fix is a gMSA or a long random password, planned with the service owner.
  - **ACC-04:** the contractor's password must change too, coordinated with them.
- **Accounts are named by their sAMAccountName, computers included** (`APP01$`, as AD writes it). One fix
  command then works for users and computers. `Set-ADAccountControl 'APP01'` fails, while `'APP01$'` works
  (tested with `-WhatIf`).
- **DEL-01 flags user and computer accounts, enabled or not**, and never a domain controller. This follows
  the catalog and PingCastle: a disabled account keeps the trust and can be re-enabled. Only a computer is
  seeded, so the user case is covered by unit tests.
- **ACC-04 matches password words, not a bare `pass`**, so there are no hits on `bypass`, `passport`,
  `Pass-the-hash notes` or `Pass-through`. The text is read, matched and dropped: only the indicator and
  the attribute name are stored.
- **References, checked at the source:**
  - PingCastle: `P-UnconstrainedDelegation` (DEL-01) and `S-ADRegistration` (DEL-05). There is none for
    KRB-03 (`P-Kerberoasting` covers admin accounts only) or ACC-04, so `null`, as PWD-02 has.
  - ATT&CK:
    - T1187 and T1550.003 (DEL-01).
    - T1558.003 (KRB-03).
    - T1552 for ACC-04: no sub-technique covers a directory attribute, and the catalog's .001 means files.
    - T1136.002 for DEL-05: our own inference; neither MITRE nor PingCastle maps it.
- **DEL-05 reads the attribute only.** Some domains keep a quota above 0 but restrict "Add workstations to
  domain" by Group Policy; ADPulse still flags them, where PingCastle does not. Group Policy settings are read
  in a later increment, and the evidence source says so.
- **KRB-03 stays mapped to ECC 2-2-3-4** (as already recorded), though it is the weakest fit of the four: a
  Kerberoastable account is not necessarily privileged. The "why it matters" text says what the account is
  and makes no claim about privilege.

## Engine

- **Collector (adsnap):** still one bind as the reader, following the dictionary in `docs/architecture.md`.
  Verified live: the reader sees every attribute below.
  - **Domain object:** add `ms-DS-MachineAccountQuota` → `machine_account_quota` (raw kept). A missing value
    becomes `None` plus an error, like the policy fields.
  - **Users:** also read `servicePrincipalName`, `description`, `info` and `comment`.
    - Raw: add `servicePrincipalName` (a list). `description`, `info` and `comment` are never stored.
    - Derived:
      - `spns` (sorted list).
      - `kerberoastable`: has an SPN and is not krbtgt. Only krbtgt is excluded; a built-in Administrator
        with an SPN is a finding.
      - `unconstrained_delegation` (`userAccountControl` bit 0x80000).
      - `password_in_text_indicator`, and `password_in_text_attrs` (the names of the attributes that
        matched).
  - **Computers:** a new query, `(objectCategory=computer)`.
    - Stored: `sAMAccountName`, `userAccountControl` and `primaryGroupID`.
    - Derived: `is_dc` (primaryGroupID 516 or 521, so read-only DCs count too) and
      `unconstrained_delegation`.
    - The name is the sAMAccountName, with its `$`.
    - A failed computer query gives partial coverage plus an error, never an abort.
  - **Password words** (case-insensitive):
    - English: `password`, `passwd`, `passphrase` and `pwd` as words. A letter may not touch either side; a
      digit may (`password1` matches).
    - `pass` counts only when followed by `:` or `=` (`pass: …`).
    - Arabic: `كلمة المرور`, `كلمة مرور`, `كلمة السر`, `كلمة سر`.
- **Test builders:**
  - A new `make_computer(name, rid=…, **derived)`, with defaults: not a DC, no delegation.
  - `make_user` and `make_domain` get safe defaults for the new fields: no SPN, no password text, quota 0.
  - `make_snapshot` adds no computer, just as it adds no user. A snapshot without computers makes DEL-01 not
    assessed; tests that want it assessed add a computer.
- **Rules:** YAML + Python, in both languages, one finding per object. Evidence uses `account`, `setting`,
  `current` and `expected`, the labels the report already translates. A missing field raises `NotAssessed`,
  never a pass (the reference plan's `del_05.py` defaulted to 0 and would have passed). A `computer_accounts()`
  helper goes next to `user_accounts()`: DEL-01 needs it now, and later increments read computers again.

  | Check | Flags | Severity | ECC | Fix in the report (`<account>` becomes the quoted name) |
  |---|---|---|---|---|
  | DEL-01 | a user, or a computer that is not a DC, with `unconstrained_delegation` | Critical | 2-2-3-4 | `Set-ADAccountControl <account> -TrustedForDelegation $false`; if a service needs delegation, use constrained or resource-based constrained delegation |
  | KRB-03 | an enabled user that is `kerberoastable` | High | 2-2-3-4 | Move the service to a gMSA. Otherwise use a long random password (Microsoft: at least 14 characters, longer is better) and AES only: `Set-ADUser <account> -KerberosEncryptionType AES128,AES256`, then `Set-ADAccountPassword <account> -Reset`. Remove SPNs that are no longer used |
  | ACC-04 | a user with `password_in_text_indicator`, enabled or not (the text is readable either way) | High | 2-2-3-1 | Remove the password from the attribute named in the evidence (a description: `Set-ADUser <account> -Clear description`), then change the password: `Set-ADAccountPassword <account> -Reset`. Anyone could read it |
  | DEL-05 | domain `machine_account_quota` > 0 | High | 2-2-3-3 | `Set-ADDomain (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0}`, then let a dedicated group join computers. This is set on the domain object: unlike the password policy (D33), no GPO re-applies it (checked 2026-09-25) |

  Evidence per check:
  - **DEL-01:** `userAccountControl`, "trusted for unconstrained delegation (TRUSTED_FOR_DELEGATION, 0x80000)".
  - **KRB-03:** `servicePrincipalName` and its value(s), e.g. `MSSQLSvc/app01.corp.local:1433`. They are not
    secrets and they tell the administrator which service is affected.
  - **ACC-04:** the attribute names, "mentions a password (the text is not stored)".
  - **DEL-05:** `ms-DS-MachineAccountQuota`, the current value against the expected 0.
- **ECC view:** picks the new checks up automatically; `ecc_2_2024.yaml` already lists all four as planned.
  - 2-2-3-3 gets its first evidence (DEL-05).
  - 2-2-3-4 gets DEL-01 and KRB-03.
  - 2-2-3-1 gets ACC-04.
- **Truth table:** a fixture that was recorded cleanly (full coverage, no errors) but before this collector
  (no computers, or no `machine_account_quota`) is skipped with "re-record on DC1". This replaces the
  domain-only skip. A fixture with collection errors is never skipped, so a real failure fails the test.
  The lab steps must end with 0 skipped.
- **Tests that change with the new checks** (all found by the review):
  - `adsnap`:
    - `test_collector.py`: rows gain the quota and SPNs; add a missing-quota test and a "description, info,
      comment never stored" test.
    - `test_derive.py` and `test_testing.py`: the exact dictionaries.
  - `adrules`:
    - `test_catalog.py`: 9 ids.
    - `test_controls.py`:
      - The planned lists.
      - 2-2-3-3 no longer "no checks".
      - "1 of 4" becomes "1 of 5".
      - ACC-04 joins the 2-2-3-1 list.
    - `test_adrules_cli.py` and `test_report.py`: summary lines and tile counts.
    - `test_lab_truth_table.py`: the skip rule.
- **Ground truth (`expected-findings.yaml`):**
  - DEL-01 now lists `APP01$`.
  - `after_fix` becomes the state after the demo fixes: KRB-03 `[svc_backup, svc_sql, svc_web]` and ACC-04
    `[contractor1]` only.
- **Docs:**
  - The `architecture.md` dictionary:
    - `spns` replaces `spn_count`.
    - Word-aware matching.
    - `unconstrained_delegation` on users.
    - `is_builtin` is no longer used by KRB-03.
    - `enabled` is no longer used by DEL-01.
  - The catalog rows: DEL-01 `is_dc` 516/521, and the references above.
  - A new "Increment 4 lab" section in `lab/README.md`, with its demo loop.

## Lab

No script changes. `Seed.ps1` already applied the increment-4 seeds, verified live on 2026-09-25:
- SPNs on `svc_sql`, `svc_web` and `svc_backup`.
- `contractor1`'s description mentions a password.
- `APP01` is trusted for unconstrained delegation.
- The quota is still 10.

Must **not** be flagged:
- `DC1`: trusted for delegation, as every DC is.
- `krbtgt`: it has the SPN `kadmin/changepw`.
- `SRV01`.
- The default descriptions, including `adpulse.reader`'s (checked: no password words).

| Lab state | Problems |
|---|---|
| `reader-ready` → `lab-default.json` | 3: PWD-01, PWD-04, DEL-05 |
| `seeded` → `lab-seeded.json` (demo start) | 10: DEL-01 `APP01$` · ACC-01 `temp.intern` · KRB-02 `svc_legacy` · KRB-03 `svc_backup`, `svc_sql`, `svc_web` · ACC-04 `contractor1` · DEL-05 · PWD-01 · PWD-04. 8 of 9 checks fail; ECC 2-2-3-1, 2-2-3-3 and 2-2-3-4 fail |
| after the demo fixes → `lab-fixed.json` | 4 still open (KRB-03 ×3, ACC-04), 6 fixed; 7 of 9 checks pass; ECC 2-2-3-3 passes, 2-2-3-1 and 2-2-3-4 still fail |

## Lab steps (with Naif)

DC1 is now in the increment-3 after-fix state. There are two reverts, each after a push. Commands run from
`C:\ADPulse\adpulse`.

1. Code pushed (tests, ruff and mypy green; review). Then a read-only check of DC1 as it is:
   `uv run adsnap collect --out $env:TEMP\inc4.json`, then `uv run adrules evaluate $env:TEMP\inc4.json`.
   Expect KRB-03 ×3, ACC-04, DEL-01 `APP01$` and DEL-05. `DC1`, `SRV01` and `krbtgt` must not be flagged.
   — done 2026-09-25: exactly those; 25 objects, no errors, no free text in the snapshot
2. Naif reverts DC1 to `reader-ready`. The agent runs `git pull` in both repos, then `uv run adsnap collect
   --out packages\adrules\tests\fixtures\lab-default.json`, checks it against the truth table, commits and
   pushes.
3. Naif reverts DC1 to `seeded`. The agent runs `git pull`, records `lab-seeded.json` the same way, then
   `uv run adrules scan` → 10 problems. Naif reads the Arabic of the four new cards (wording check by a native
   speaker).
4. Naif, in his own elevated PowerShell, pasting the commands from the report:
   - The increment-3 fixes: the Default Domain Policy, then `temp.intern` and `svc_legacy`.
   - `Set-ADAccountControl 'APP01$' -TrustedForDelegation $false`.
   - `Set-ADDomain (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0}`.
   - `gpupdate /target:computer /force`.

   Then the agent runs `uv run adrules scan` → 6 resolved, 4 still open, and records `lab-fixed.json`.
5. Truth table green on all three fixtures (0 skipped). Update the demo script in the notes repo: 10
   problems, 6 fixed, 4 still open. Docs, status, build log; push. DC1 stays in this after-fix state for
   increment 5.

## Done when

pytest (0 skipped), ruff and mypy are green. The live scan from `seeded` shows the 10 problems by name in
both languages, with commands that work when pasted, and the demo fixes resolve 6 and leave 4 still open.
Naif has checked the Arabic. Everything is pushed.

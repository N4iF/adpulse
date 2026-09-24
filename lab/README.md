# lab — the ADPulse test domain in VMware

Reusable lab for developing and demonstrating ADPulse. Never use these scripts against a real domain.

## How we work (D30, 2026-09-23)

Development happens **inside the domain controller**: Claude Code runs in PowerShell on `DC1`, in the
workspace `C:\ADPulse\` (this repo is `C:\ADPulse\adpulse\`). Code, tests, the collector and the lab
scripts all run there. The host PC only runs VMware and holds the snapshots. Setup: `docs/SETUP.md`.

## Topology (D32)

```
VMware Workstation — one network 192.168.50.0/24 with internet access
  DC1     192.168.50.10    dc1.corp.local   — AD DS, DNS, LDAPS (after Setup-Lab.ps1), dev tools, Claude Code
  SRV01   192.168.50.210   srv01.corp.local — domain-joined Windows 10 client (the later DEL-01 target)
```

No AD CS, no extra VMs, no scale seeding in Phase 1 (D29). Use the real DNS name `dc1.corp.local`
everywhere (LDAPS validates the host name); older documents that say `DC01` mean this machine.

## Lab inventory

| Item | Value |
|---|---|
| Domain DNS / NetBIOS name | corp.local / CORP (forest and domain functional level 2016) |
| Domain created | 2026-09-24 |
| DC name / IP | DC1 (dc1.corp.local) / 192.168.50.10 |
| Other machine name / IP | SRV01 (srv01.corp.local) / 192.168.50.210 — Windows 10 Enterprise Evaluation |
| DC operating system | Windows Server 2022 Standard Evaluation, build 20348 |
| DC time source | internet NTP (`time.windows.com`, `pool.ntp.org`), set 2026-09-24 |
| Python on DC1 | 3.12.0 (per-user install), used by `uv` |
| Snapshot `clean` taken | 2026-09-24 |
| Snapshot `seeded` taken | 2026-09-24 (after `Setup-Lab.ps1`, before any scan) |

## Snapshot discipline

A VMware snapshot revert also reverts the workspace on DC1's disk.

1. **Before any revert:** commit and push from DC1; `git status` must be clean in every repo.
2. **After any revert:** `git pull` in every repo before anything else.
3. Naif takes and reverts snapshots on the host (VMware UI or `vmrun`); a session inside the VM cannot
   revert its own machine.

Snapshots: `clean` (domain built, dev tools installed, Active Directory unchanged) and `seeded` (after
`Setup-Lab.ps1`: reader account and LDAPS ready, password policy still the Windows default — the demo's
starting point; later increments add `Seed.ps1`). For the laptop demo, copy the VM folders (or export to
OVF) and open them in VMware on the laptop.

## Build

| Step | Where / who |
|---|---|
| 1. `DC1` (Windows Server 2022) and `SRV01` (Windows 10) on one VMware network with static IPs; SRV01's DNS points to DC1 | host, Naif — done |
| 2. Promote DC1 (new forest `corp.local`); join SRV01 to the domain | DC1 / SRV01, Naif — done |
| 3. Install dev tools and Claude Code on DC1, create the workspace (`docs/SETUP.md`) | DC1, Naif — done |
| 4. Snapshot `clean` | host, Naif — done |
| 5. MVP-1: run `Setup-Lab.ps1` in an elevated PowerShell on DC1 | DC1 |
| 6. Snapshot `seeded` | host, Naif |

## MVP-1 lab (D31, D33) — the only lab work before MVP-1 is green

ADPulse only reads. The lab scripts never change the password policy (D33): a fresh domain is already
the "before" state, and the fix is made by hand, the way an administrator would make it.

| Script (elevated PowerShell on DC1) | What it does |
|---|---|
| `Setup-Lab.ps1` | One-time setup. Creates `adpulse.reader` (Domain Users only) with a generated password and writes `.env` at the repo root (git-ignored). Creates a self-signed LDAPS certificate for the DC's DNS name if none exists, trusts it on the DC, loads it into AD DS without restarting NTDS, waits until port 636 answers, and exports it as PEM to `lab/dc-ldaps.pem` (git-ignored). Changes nothing else. Re-running it resets the reader's password and rewrites `.env`. |

**Demo loop:**

1. Fresh domain (minimum length 7, complexity on, lockout threshold 0) → `uv run adrules scan` →
   3 checks: 2 failed (PWD-01, PWD-04), 1 passed (PWD-02); new 2.
2. Fix it as an administrator would: Group Policy Management → Default Domain Policy → Edit → Computer
   Configuration → Policies → Windows Settings → Security Settings → Account Policies. Password Policy:
   minimum password length 14. Account Lockout Policy: threshold 5, duration and reset counter 15 minutes.
   Then `gpupdate /target:computer /force` and check with `Get-ADDefaultDomainPasswordPolicy` (14 / True / 5).
3. `uv run adrules scan` → 0 failed; resolved 2.

**Why not a script that sets the policy:** `Set-ADDefaultDomainPasswordPolicy` writes the domain object,
but on a DC the Default Domain Policy GPO re-applies its own account-policy values — every 16 hours, on
`gpupdate /force`, after any GPO change and probably after a snapshot revert (verified on DC1
2026-09-24: Security extension `MaxNoGPOListChangesInterval` = 960 minutes; the GPO holds 7 / 1 / 0). A
change made only on the domain object can therefore silently revert and produce a false "resolved" or
a finding that comes back. The fix in the GPO itself is both the real-world remediation and stable.

## Later increments — what the full `Seed.ps1` will create

Not built before MVP-1 works. Each row arrives with its increment (numbers in `PROJECT-STATUS.md`). The
DEL-01 item uses `SRV01` (domain-joined); the computer object `APP01` is the fallback. Any seed or fix
that touches domain password or lockout settings goes through the Default Domain Policy GPO, never the
domain object (D33).

| Item | Detail |
|---|---|
| OU `Lab`, groups `helpdesk`, users `svc_sql`, `svc_web`, `svc_backup`, `svc_legacy`, `temp.intern`, `contractor1`, `hd.user1` (member of helpdesk) | the cast |
| DEL-01 | `TrustedForDelegation` on computer account `SRV01` (or `APP01`, a computer object only) |
| DEL-05 | `ms-DS-MachineAccountQuota` left at the default 10 |
| ACL-01 | both replication extended rights for `svc_backup` on the domain head (**not** helpdesk) |
| ACL-03 | `GenericWrite` for `helpdesk` on `svc_sql` — the designed path edge |
| PRV-04 | `svc_sql` has an SPN and is a member of Domain Admins |
| KRB-01 | krbtgt never rotated since forest creation; `pwdLastSet` cannot be back-dated, so on a fresh lab the demo runs with `--krbtgt-max-age-days` low enough and the report states the threshold used |
| KRB-02 | `DONT_REQ_PREAUTH` on `svc_legacy` |
| KRB-03 | SPNs on `svc_sql`, `svc_web`, `svc_backup` |
| GPO-01 | test GPO `Lab-Legacy` with a `Groups.xml` containing a `cpassword` in its SYSVOL folder (the collector never reads the value) |
| ACC-01 | `PASSWD_NOTREQD` on enabled user `temp.intern` |
| ACC-04 | `description` = "temp password: …" on `contractor1` |
| PWD-01 | none needed: the Windows default minimum length (7) already fails |

**Designed path (demo):** `helpdesk —GenericWrite→ svc_sql —MemberOf→ Domain Admins`. `Fix-ACL-03.ps1`
removes the GenericWrite ACE, ACL-03 becomes `resolved` and the path disappears. No other seed may give
`helpdesk` a route to Tier 0.

**Clean baseline (full scope):** besides PWD-01 and PWD-04 above, a default domain also fails DEL-05
(default quota) and possibly KRB-01 (threshold-dependent); `expected-findings.yaml` records each baseline
finding as its increment lands.

`expected-findings.yaml` = expected state → actual state → finding: the ground-truth dataset for the lab
acceptance criteria (100% detection of seeded findings, 0 unexpected findings on the clean baseline, every
result with reproducible evidence, every remediation causing the expected lifecycle transition).

## Scripts

MVP-1: `Setup-Lab.ps1`. Later increments: `Seed.ps1`, `Drift.ps1`, one `Fix-<check>.ps1` per check. All
run inside DC1 in an elevated PowerShell. Reset and export are VMware operations on the host (see
"Snapshot discipline"), not scripts.

## `.env` on DC1 (git-ignored, repo root, written by `Setup-Lab.ps1`)

```
ADPULSE_DC=dc1.corp.local
ADPULSE_DOMAIN=corp.local
ADPULSE_USER=adpulse.reader@corp.local
ADPULSE_PASSWORD=...
ADPULSE_MODE=standard
ADPULSE_CA_CERT=lab/dc-ldaps.pem
```

## Rejected for Phase 1

Hyper-V (replaced by VMware on 2026-09-23, D30), AutomatedLab, BadBlood and vulnerable-AD (noise we
don't need), GOAD/Ludus, an AD CS server (only PKI-01 needs it — after the Cyberthon), scripts that set
the password policy on the domain object (D33).

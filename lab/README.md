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
  SRV01   192.168.50.210   srv01.corp.local — domain-joined Windows 10 client
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
| Snapshot `reader-ready` | 2026-09-24 (after `Setup-Lab.ps1`, before `Seed.ps1` and any scan; taken as `seeded`, renamed 2026-09-25) |
| Snapshot `seeded` taken | 2026-09-25 (after `Seed.ps1`, before any scan — the demo start) |

## Snapshot discipline

A VMware snapshot revert also reverts the workspace on DC1's disk.

1. **Before any revert:** commit and push from DC1; `git status` must be clean in every repo.
2. **After any revert:** `git pull` in every repo before anything else.
3. Naif takes and reverts snapshots on the host (VMware UI or `vmrun`); a session inside the VM cannot
   revert its own machine.

Snapshots: `clean` (domain built, dev tools installed, Active Directory unchanged), `reader-ready` (after
`Setup-Lab.ps1`: reader and LDAPS, no organization — revert here to record `lab-default.json` again when the
collector reads more) and `seeded` (after `Seed.ps1` too: the organization and its seeds, password policy
still the Windows default, no scans yet — the demo's starting point). For the laptop demo, copy the VM folders (or export to
OVF) and open them in VMware on the laptop.

## Build

| Step | Where / who |
|---|---|
| 1. `DC1` (Windows Server 2022) and `SRV01` (Windows 10) on one VMware network with static IPs; SRV01's DNS points to DC1 | host, Naif — done |
| 2. Promote DC1 (new forest `corp.local`); join SRV01 to the domain | DC1 / SRV01, Naif — done |
| 3. Install dev tools and Claude Code on DC1, create the workspace (`docs/SETUP.md`) | DC1, Naif — done |
| 4. Snapshot `clean` | host, Naif — done |
| 5. MVP-1: run `Setup-Lab.ps1` in an elevated PowerShell on DC1 | DC1 — done |
| 6. Increment 3: run `Seed.ps1` in an elevated PowerShell on DC1 | DC1 — done 2026-09-25 |
| 7. Snapshot `seeded` (retaken after `Seed.ps1`; the old one kept as `reader-ready`) | host, Naif — done 2026-09-25 |

## MVP-1 lab (D31, D33) — the only lab work before MVP-1 is green

ADPulse only reads. The lab scripts never change the password policy (D33): a fresh domain is already
the "before" state, and the fix is made by hand, the way an administrator would make it.

| Script (elevated PowerShell on DC1) | What it does |
|---|---|
| `Setup-Lab.ps1` | One-time setup. Creates `adpulse.reader` (Domain Users only) with a generated password and writes `.env` at the repo root (git-ignored). Creates a self-signed LDAPS certificate for the DC's DNS name if none exists, trusts it on the DC, loads it into AD DS without restarting NTDS, waits until port 636 answers, and exports it as PEM to `lab/dc-ldaps.pem` (git-ignored). Changes nothing else. Re-running it resets the reader's password and rewrites `.env`. |

**Demo loop:**

1. Fresh domain (minimum length 7, complexity on, lockout threshold 0) → `uv run adrules scan` →
   2 failed (PWD-01, PWD-04), the other checks passed; new 2.
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

## Increment 3 lab — the organization (`Seed.ps1`)

`Seed.ps1` (elevated PowerShell on DC1; Naif's OK; idempotent; never touches the password policy or
`adpulse.reader`) turns the empty domain into a small organization, so findings appear among ordinary
accounts. Random passwords, never printed or stored; nobody signs in with these accounts.

| Object | Detail |
|---|---|
| `OU=Lab` → `Staff`, `ServiceAccounts`, `Groups`, `Servers` | the organization |
| staff | `it.fahad`, `it.sara`, `hr.noura`, `hr.omar`, `fin.khalid`, `fin.lama`, `sales.reem`, `sales.yousef`, `ops.maha`, `ops.turki` — one department group each |
| groups | `GRP-IT`, `GRP-HR`, `GRP-Finance`, `GRP-Sales`, `GRP-Operations`, `helpdesk` |
| `hd.user1` | help desk agent, member of `helpdesk` and `GRP-IT` |
| `temp.intern`, `contractor1` | temporary staff |
| service accounts | `svc_sql`, `svc_web`, `svc_backup`, `svc_legacy` |
| `APP01` | computer object in `Servers` (no VM) |

**Seeds (weaknesses)** — each check sees its seed once the check exists:

| Increment | Check | Seed |
|---|---|---|
| 3 | ACC-01 | `temp.intern`: password not required |
| 3 | KRB-02 | `svc_legacy`: Kerberos pre-authentication off |
| 4 | KRB-03 | SPNs on `svc_sql`, `svc_web`, `svc_backup` |
| 4 | ACC-04 | `contractor1` description mentions a password (no real password in it) |
| 4 | DEL-01 | `APP01` trusted for unconstrained delegation |
| 4 | DEL-05 | machine account quota left at the default 10 |
| 5 | ACL-01, ACL-03, PRV-04 | not seeded yet — see the note below |
| 6 | GPO-01 | not seeded yet: an unlinked test GPO `Lab-Legacy` with a `cpassword` in `Groups.xml` |
| 6 | KRB-01 | none possible: krbtgt was set at forest creation; the check's threshold is a parameter |
| — | PWD-01, PWD-04 | none needed: the Windows defaults already fail |

**Increment-3 demo loop:** from snapshot `seeded` → `uv run adrules scan` → 4 problems to fix (PWD-01,
PWD-04, ACC-01 `temp.intern`, KRB-02 `svc_legacy`) → fix the password policy in the Default Domain Policy
(above) and the two accounts with the commands shown in the report → `gpupdate /target:computer /force` →
`uv run adrules scan` → 4 fixed.

**Note for increment 5 (checked 2026-09-25):** the path first designed here — `helpdesk —GenericWrite→
svc_sql —MemberOf→ Domain Admins` — does not hold. Members of Domain Admins are protected by
AdminSDHolder: SDProp resets their permissions about every hour, which would remove the helpdesk ACE and
break the demo. Increment 5 designs the path and its seeds again (ACL-01, ACL-03, PRV-04), and no seed may
give `helpdesk` a second route to Tier 0.

**Clean baseline (full scope):** besides PWD-01 and PWD-04 above, a default domain also fails DEL-05
(default quota) and possibly KRB-01 (threshold-dependent); `expected-findings.yaml` records each baseline
finding as its increment lands.

`expected-findings.yaml` = expected state → actual state → finding: the ground-truth dataset for the lab
acceptance criteria (100% detection of seeded findings, 0 unexpected findings on the clean baseline, every
result with reproducible evidence, every remediation causing the expected lifecycle transition).

## Scripts

`Setup-Lab.ps1` (MVP-1: reader and LDAPS) and `Seed.ps1` (increment 3: the organization and seeds). Later,
if needed: `Drift.ps1`, `Fix-<check>.ps1`. All run inside DC1 in an elevated PowerShell. Reset and export are VMware operations on the host (see
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

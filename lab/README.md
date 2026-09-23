# lab — the ADPulse test domain in VMware

Reusable lab for developing and demonstrating ADPulse. Never use these scripts against a real domain.

## How we work (D30, 2026-09-23)

Development happens **inside the domain controller**: Claude Code runs in PowerShell on `DC01`, in a git
clone of this repo. Code, tests, the collector and the lab scripts all run there. The host PC only runs
VMware and holds the snapshots. Setup: `docs/SETUP.md`.

## Topology

```
VMware Workstation — both VMs on the NAT network (VMnet8), internet via NAT
  DC01    <static IP>   dc01.corp.local — AD DS, DNS, LDAPS, dev tools, Claude Code
  SRV01   <static IP>   srv01.corp.local — member server
```

No AD CS, no client VM, no scale seeding in Phase 1 (D29). If the machines already use other names,
domain or IPs, the first session inside DC01 records the real values below and in `.env`.

## Lab inventory (fill in on the first session inside DC01)

| Item | Value |
|---|---|
| Domain DNS / NetBIOS name | corp.local / CORP |
| DC name / IP | DC01 / ______ |
| Member server name / IP | SRV01 / ______ |
| Windows Server version and build | ______ |
| Snapshot `clean` taken | ______ |
| Snapshot `seeded` taken | ______ |

## Snapshot discipline

A VMware snapshot revert also reverts the git clone on DC01's disk.

1. **Before any revert:** commit and push from DC01; `git status` must be clean in every repo.
2. **After any revert:** `git pull` in every repo before anything else.
3. Naif takes and reverts snapshots on the host (VMware UI or `vmrun`); a session inside the VM cannot
   revert its own machine.

Snapshots: `clean` (domain built, dev tools installed, nothing seeded) and `seeded` (after `Seed.ps1`).
For the laptop demo, copy the VM folders (or export to OVF) and open them in VMware on the laptop.

## Build

| Step | Where / who |
|---|---|
| 1. Two Windows Server 2022 VMs on VMnet8 with static IPs; SRV01's DNS points to DC01 | host, Naif |
| 2. Promote DC01 (`Install-DC.ps1`, only if the forest does not exist yet); join SRV01 to the domain | DC01 / SRV01, elevated PowerShell |
| 3. Install dev tools and Claude Code on DC01, clone the repos (`docs/SETUP.md`) | DC01, Naif |
| 4. Snapshot `clean` | host, Naif |
| 5. Run `Seed.ps1` in an elevated PowerShell on DC01 (items below) | DC01 |
| 6. Snapshot `seeded` | host, Naif |

The DEL-01 item below uses the real member server `SRV01` when it is joined to the domain; the computer
object `APP01` is the fallback when there is no second server.

## What `Seed.ps1` creates

| Item | Detail |
|---|---|
| LDAPS | self-signed certificate for `dc01.corp.local` in the DC's machine store (`New-SelfSignedCertificate -DnsName dc01.corp.local`); LDAPS on 636 starts working on restart of the NTDS service. The collector trusts this certificate explicitly (`ADPULSE_CA_CERT` or `--insecure-lab`). |
| `adpulse.reader` | member of Domain Users only — the collector's identity in standard mode |
| OU `Lab`, groups `helpdesk`, users `svc_sql`, `svc_web`, `svc_backup`, `svc_legacy`, `temp.intern`, `contractor1`, `hd.user1` (member of helpdesk) | the cast |
| DEL-01 | `TrustedForDelegation` on computer account `APP01` (a computer object only; no VM needed) |
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
| PWD-01 | `Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 6` |

**Designed path (demo):** `helpdesk —GenericWrite→ svc_sql —MemberOf→ Domain Admins`. `Fix-ACL-03.ps1`
removes the GenericWrite ACE, ACL-03 becomes `resolved` and the path disappears. No other seed may give
`helpdesk` a route to Tier 0.

**Clean baseline:** the `clean` checkpoint must produce zero Tier A findings except DEL-05 (default
quota) and possibly KRB-01 (threshold-dependent); both are documented in `expected-findings.yaml`.

`expected-findings.yaml` = expected state → actual state → finding: the ground-truth dataset for the lab
acceptance criteria (100% detection of seeded findings, 0 unexpected findings on the clean baseline, every
result with reproducible evidence, every remediation causing the expected lifecycle transition).

## Scripts (to be written in Phase 1)

`Install-DC.ps1`, `Seed.ps1`, `Drift.ps1` (changes lab state between scans for the lifecycle demo),
`Fix-<check>.ps1` for each of the 12 checks. All run inside DC01 in an elevated PowerShell. Reset and
export are VMware operations on the host (see "Snapshot discipline"), not scripts.

## `.env` on DC01 (git-ignored, repo root)

```
ADPULSE_DC=dc01.corp.local
ADPULSE_DOMAIN=corp.local
ADPULSE_USER=adpulse.reader@corp.local
ADPULSE_PASSWORD=...
ADPULSE_MODE=standard
ADPULSE_CA_CERT=lab/dc01-ldaps.cer   # exported self-signed certificate
```

## Rejected for Phase 1

Hyper-V (replaced by VMware on 2026-09-23, D30), AutomatedLab, BadBlood and vulnerable-AD (noise we
don't need for 12 checks), GOAD/Ludus, an AD CS server (only PKI-01 needs it — Tier B).

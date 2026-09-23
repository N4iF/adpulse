# lab — a deliberately misconfigured Active Directory on Hyper-V (one VM)

Reusable lab for developing and demonstrating ADPulse. Never use these scripts against a real domain;
they create intentional weaknesses. Steps marked **[admin]** need an elevated PowerShell on the host.

## Topology (Phase 1: one domain controller, nothing else)

```
Hyper-V Internal switch "LABNET" 10.10.10.0/24
  Host   10.10.10.1    development box (collector, tests, apps)
  DC01   10.10.10.10   dc01.corp.local — AD DS, DNS, LDAPS   Windows Server 2022 eval, 2 vCPU, 4 GB, 60 GB
```

The same VM is the "lite lab": export the `seeded` checkpoint and import it on the laptop. Extra VMs
(a client, an AD CS server), scale seeding (BadBlood) and vulnerable-AD are Tier B.

## Build (about 45 minutes once, then minutes from checkpoints)

| Step | How | Who |
|---|---|---|
| 1. Hyper-V switch | `New-VMSwitch -Name LABNET -SwitchType Internal`; give the host adapter 10.10.10.1/24; hosts file: `10.10.10.10 dc01.corp.local corp.local` | [admin] |
| 2. ISO | Windows Server 2022 evaluation (Desktop Experience) from the Microsoft Evaluation Center into `lab/ISOs/` (git-ignored) | Naif |
| 3. VM + OS | `New-VM DC01 -Generation 2 -MemoryStartupBytes 4GB -SwitchName LABNET`, attach ISO, install Windows by hand (~20 min), set the local Administrator password | [admin] |
| 4. Promote | copy `Install-DC.ps1` in (PowerShell Direct: `Copy-VMFile`), run it inside DC01: rename, static IP 10.10.10.10, `Install-ADDSForest -DomainName corp.local`, reboot | script |
| 5. Checkpoint | `Checkpoint-VM DC01 -SnapshotName clean` | [admin] |
| 6. Seed | run `Seed.ps1` inside DC01 (`Invoke-Command -VMName DC01`) — see table below | script |
| 7. Checkpoint | `Checkpoint-VM DC01 -SnapshotName seeded` | [admin] |

`Reset.ps1` = `Restore-VMSnapshot DC01 -Name seeded` (under 2 minutes). `Export-Lab.ps1` exports DC01
for the laptop.

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

`Install-DC.ps1`, `Seed.ps1`, `Drift.ps1` (add an SPN, grant a bad ACE, disable an account, fix one
finding), `Fix-<check>.ps1` for each of the 12 checks, `Reset.ps1`, `Export-Lab.ps1`.

## Host `.env` (git-ignored)

```
ADPULSE_DC=dc01.corp.local
ADPULSE_DOMAIN=corp.local
ADPULSE_USER=adpulse.reader@corp.local
ADPULSE_PASSWORD=...
ADPULSE_MODE=standard
ADPULSE_CA_CERT=lab/dc01-ldaps.cer   # exported self-signed certificate
```

## Rejected for Phase 1

AutomatedLab (heavy module for one VM), BadBlood and vulnerable-AD (noise we don't need for 12 checks),
GOAD/Ludus (no Hyper-V), a second VM with AD CS (only PKI-01 needs it — Tier B).

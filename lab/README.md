# lab — deliberately misconfigured Active Directory on Hyper-V

Generic, reusable lab builders for developing and demonstrating ADPulse. Never use these scripts against
a real domain; they create intentional weaknesses. Steps marked **[admin]** need an elevated PowerShell
on the host; an AI session cannot do them.

## Topology

```
Hyper-V Internal switch "LABNET" 10.10.10.0/24
  Host   10.10.10.1    development box (collector, tests, apps)
  DC01   10.10.10.10   corp.local — AD DS, DNS           Windows Server 2022 eval, 2 vCPU, 4 GB, 60 GB
  SRV01  10.10.10.20   member — AD CS enterprise CA, SMB  Windows Server 2022 eval, 2 vCPU, 4 GB, 60 GB
  WS01   10.10.10.50   member — Win11 client (optional)   Windows 11 Enterprise eval, 2 vCPU, 4 GB, 60 GB
```

**Lite lab (16 GB laptop):** `DC01` only, exported from the *seeded* full lab (`Export-LiteLab.ps1`).
Certificate templates and enrollment services live in the Configuration NC that DC01 holds, so PKI-01 is
still assessable; CA-host checks (PKI-05/06/09, `ca_registry` coverage) report `not_assessed`.

## Prerequisites

| Step | Who |
|---|---|
| Enable Hyper-V; create the Internal switch `LABNET`; give the host adapter 10.10.10.1/24. | [admin] |
| Download Windows Server 2022 and Windows 11 Enterprise evaluation ISOs into `lab/LabSources/ISOs/` (git-ignored). | Naif |
| Install the AutomatedLab PowerShell module on the host. | [admin] |
| LDAPS: DC01 needs a server certificate. `01-Build-Lab.ps1` installs an enterprise root CA on SRV01; DC01 auto-enrolls a Domain Controller certificate and LDAPS (636) starts working. Export DC01 for the lite lab only after that enrollment. | script |
| Standard-user account `adpulse.reader` (member of Domain Users only) — the collector's identity in standard mode. `04-Seed-Extras.ps1` creates it. | script |
| Host name resolution: add `10.10.10.10 dc01.corp.local corp.local` to the hosts file, or point the LABNET adapter's DNS at DC01. The collector must use the DNS name (`dc01.corp.local`), not the IP — LDAPS validates the hostname. | [admin] |
| `.env` at the repo root (git-ignored): `ADPULSE_DC=dc01.corp.local`, `ADPULSE_DOMAIN=corp.local`, `ADPULSE_USER=adpulse.reader@corp.local`, `ADPULSE_PASSWORD=…`, `ADPULSE_MODE=standard`. | Naif |

## Build sequence (run from the host; in-VM steps use PowerShell Direct)

| Script | Purpose | Result |
|--------|---------|--------|
| `01-Build-Lab.ps1` | AutomatedLab: VMs, forest `corp.local`, AD CS enterprise root on SRV01, DC certificate enrollment | checkpoint `clean` |
| `02-BadBlood.ps1` | thousands of realistic objects + randomized ACLs (scale) | — |
| `03-VulnAD.ps1` | vulnerable-AD `Invoke-VulnAD` | — |
| `04-Seed-Extras.ps1` | the Tier A seeds below, the designed path, `adpulse.reader`; driven by `expected-findings.yaml` | checkpoint `seeded` |
| `05-Drift.ps1` | between scans: add an SPN, grant a bad ACE, disable an account, fix one finding | — |
| `Fix-<check>.ps1` | remediation per check (`Fix-ACL-03.ps1` is the on-stage fix) | — |
| `Reset-Lab.ps1` | restore `seeded` in under 2 minutes | — |
| `Export-LiteLab.ps1` | export DC01 `seeded` for the laptop | — |

## Tier A seeds (what `04-Seed-Extras.ps1` must create)

| Check | Seed | Notes |
|---|---|---|
| DEL-01 | `TrustedForDelegation` on SRV01 | non-DC computer |
| DEL-05 | leave `ms-DS-MachineAccountQuota` at the default 10 | fires on any default domain |
| ACL-01 | DCSync rights (both replication extended rights) for `svc_backup` on the domain head | **not** helpdesk, so the designed path stays helpdesk's only route |
| ACL-03 | `GenericWrite` for group `helpdesk` on user `svc_sql` | the designed path edge |
| PRV-04 | `svc_sql` has an SPN and is a member of Domain Admins | krbtgt excluded by rule |
| KRB-01 | krbtgt password never rotated since forest creation | `pwdLastSet` cannot be back-dated; for a fresh lab the demo passes `--krbtgt-max-age-days` low enough, and the report states the threshold used |
| KRB-02 | `DONT_REQ_PREAUTH` on `svc_legacy` | — |
| KRB-03 | SPNs on `svc_sql`, `svc_web`, `svc_backup` | — |
| PKI-01 | template `UserAuthLab`: enrollee supplies subject, Client Authentication EKU, no manager approval, 0 signatures, published on the CA, Enroll for Domain Users | — |
| GPO-01 | a legacy `Groups.xml` with a `cpassword` under a test GPO's SYSVOL folder | value is never read by the collector |
| ACC-01 | `PASSWD_NOTREQD` on enabled user `temp.intern` | built-in Guest excluded by rule |
| ACC-04 | `description` = "temp password: …" on user `contractor1` | evidence = attribute name only |

**Designed path (demo):** `helpdesk —GenericWrite→ svc_sql —MemberOf→ Domain Admins`. Removing the
GenericWrite ACE (`Fix-ACL-03.ps1`) makes ACL-03 `resolved` and the path disappear. No other seed may give
`helpdesk` a route to Tier 0.

**Clean baseline:** the `clean` checkpoint must produce zero Tier A findings except DEL-05 (default quota)
and possibly KRB-01 (threshold-dependent); both are documented in `expected-findings.yaml`.

`expected-findings.yaml` = expected state → actual state → finding: the ground-truth dataset for the lab
acceptance criteria (100% detection of seeded findings, 0 unexpected findings on the clean baseline, every
result with reproducible evidence, every remediation causing the expected lifecycle transition).

## Rejected alternatives

GOAD / Ludus (no Hyper-V support; Linux-only tooling), DetectionLab (unmaintained), VMware (not needed).

## Status

Scripts are not written yet (Phase 1). This README is the contract they implement.

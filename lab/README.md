# lab — deliberately misconfigured Active Directory on Hyper-V

Generic, reusable lab builders for developing and demonstrating ADPulse. Never use these scripts against
a real domain; they create intentional weaknesses.

## Topology

```
Hyper-V Internal switch "LABNET" 10.10.10.0/24
  Host   10.10.10.1    development box (collector, tests, apps)
  DC01   10.10.10.10   corp.local — AD DS, DNS           Windows Server 2022 eval, 2 vCPU, 4 GB, 60 GB
  SRV01  10.10.10.20   member — AD CS enterprise CA, SMB  Windows Server 2022 eval, 2 vCPU, 4 GB, 60 GB
  WS01   10.10.10.50   member — Win11 client (optional)   Windows 11 Enterprise eval, 2 vCPU, 4 GB, 60 GB
```

Lite lab (16 GB laptop): `DC01` only; AD CS checks report `not_assessed`.

## Build sequence (run from the host; in-VM steps use PowerShell Direct)

| Script | Purpose | Result |
|--------|---------|--------|
| `01-Build-Lab.ps1` | AutomatedLab: VMs, forest `corp.local`, AD CS role on SRV01 | checkpoint `clean` |
| `02-BadBlood.ps1` | thousands of realistic objects + randomized ACLs (scale) | — |
| `03-VulnAD.ps1` | vulnerable-AD `Invoke-VulnAD` (kerberoast, AS-REP, ACL abuse, DCSync rights, password in description, SMB signing off) | — |
| `04-Seed-Extras.ps1` | the exact findings a product slice needs (e.g., the 12 MVP checks + one designed potential privilege-escalation path), driven by `expected-findings.yaml` | checkpoint `seeded` |
| `05-Drift.ps1` | between scans: add an SPN, grant a bad ACE, disable an account, fix one finding — for the lifecycle story | — |
| `Fix-<check>.ps1` | remediation per check (used in demos and regression tests) | — |
| `Reset-Lab.ps1` | restore `seeded` in under 2 minutes | — |
| `Export-LiteLab.ps1` | export DC01 `seeded` checkpoint for the laptop | — |

`expected-findings.yaml` = expected state → actual state → finding. It is the ground-truth dataset for
lab acceptance criteria (100% detection of seeded findings, 0 unexpected findings on the clean baseline,
every result with reproducible evidence, every remediation causing the expected lifecycle transition).

## Rejected alternatives

GOAD / Ludus (no Hyper-V support; Linux-only tooling), DetectionLab (unmaintained), VMware (not needed).

## Media

Windows Server 2022 evaluation (180-day) and Windows 11 Enterprise evaluation (90-day) from the Microsoft
Evaluation Center. ISOs are not committed (see `.gitignore`).

## Status

Scripts are not written yet (Phase 1). This README is the contract they implement.

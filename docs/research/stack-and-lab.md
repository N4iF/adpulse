# Collection stack and lab research (2026-09-21, versions re-verified 2026-09-22)

## 1. Data collection options

### 1.1 Capability matrix

| Collector | ACLs / DACLs | GPO contents | Pwd policy + FGPP | Kerberos (SPN / deleg / AS-REP) | ADCS templates | LAPS | Trusts | DC config | Auth | Host OS | Maturity |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **ldap3** (Python) | Raw `nTSecurityDescriptor` bytes; needs an external parser | Metadata only (`gPLink`, GPO objects); files need SMB | Yes (domain root attrs + Password Settings Container) | Yes (`servicePrincipalName`, `userAccountControl`, `msDS-AllowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity`) | Yes (Configuration NC) | Yes (`ms-Mcs-AdmPwd*`, `msLAPS-*`) | Yes (`trustedDomain`) | Partial (LDAP attrs only) | Simple/NTLM/SASL-GSSAPI; LDAPS 636 | Win + Linux | Very mature; huge install base |
| **msldap** (skelsec) | Parsed via `winacl` | Metadata + GPO objects | Yes | Yes | First-class template/CA objects | Yes | Yes | Partial | URL strings (`ldap+ntlm-password://`, kerberos, sspi); channel binding & signing | Win + Linux | Active; asyncio; steeper learning curve |
| **impacket** | `impacket.ldap.ldaptypes` parses SD/ACL/ACE binary | **Real file contents** via `SMBConnection`/`smbclient.py` on `\\dc\SYSVOL` | via its LDAP | `GetUserSPNs.py`, `GetNPUsers.py` | via LDAP | via LDAP | via LDAP | SMB dialect/signing observable | NTLM / Kerberos / PtH | Win + Linux | Very mature |
| **PowerShell `ActiveDirectory` + `GroupPolicy`** | `Get-Acl AD:\<DN>` returns named rights | Best: `Get-GPOReport -All -ReportType Xml` | `Get-ADDefaultDomainPasswordPolicy`, `Get-ADFineGrainedPasswordPolicy` | Full | via `Get-ADObject` on Configuration NC | Yes | `Get-ADTrust` | Best (+ registry, `Get-SmbServerConfiguration`) | Integrated Windows auth | Windows only, RSAT | Microsoft-supported |
| **BloodHound CE / SharpHound** | Abusable rights pre-resolved to edge names | Links + OU tree only | No | Delegation + SPN signals | Yes (`CertTemplates`, `EnterpriseCAs`, `RootCAs`, `NTAuthStores`, `IssuancePolicies`) | Partial (`CanReadLAPSPassword`) | Yes | Sessions/local admin only | Domain user | SharpHound = Windows; `bloodhound-ce` py = Linux | Attack-path-shaped, not config-shaped |
| **ADRecon** | ACLs (DACL+SACL), opt-in | `GPOReport` (needs RSAT) | Yes | Yes (`Kerberoast` module opt-in) | No dedicated module | Yes + BitLocker keys | Yes | DCs, SMB versions, signing, FSMO | Domain user; ADWS or LDAP | Windows (PS); CSV/Excel | Maintained fork; tabular output |
| **PingCastle XML** | Derived findings only | Derived GPO findings incl. GPP passwords | Derived | Derived (e.g., `P-UnconstrainedDelegation`) | Derived (`A-CertTempAgent`, `A-CertTempAnyPurpose`) | Derived | Yes + trust scoring | Yes | Domain user | Windows .NET binary | Mature; licence caveat |

### 1.2 The two details that bite

**Reading `nTSecurityDescriptor` as a standard user.** A plain read also requests the SACL, which needs
`SeSecurityPrivilege`; as a normal user the attribute comes back empty. Send the `LDAP_SERVER_SD_FLAGS`
control, OID `1.2.840.113556.1.4.801` (verified in MS-ADTS 3.1.1.3.4.1.11), BER-encoded
`SEQUENCE { INTEGER flags }` with flags `0x07` (OWNER | GROUP | DACL; bit values 0x1/0x2/0x4/0x8, default
0x0F when the control is absent). ldap3 literal control value for 0x07: `b'\x30\x03\x02\x01\x07'`. That
0x07 yields the DACL for an unprivileged reader is an inference from MS-ADTS 3.1.1.4.4 (reading requires
ACCESS_SYSTEM_SECURITY only when the SACL is requested) and long-standing operational behaviour (BloodHound
works unprivileged); confirm empirically in the lab.

**Python libraries that parse security descriptors:**

| Library | Binary SD parse | SDDL in/out | Rights → names | Extended-right GUID → name |
|---|---|---|---|---|
| `winacl` (skelsec) — PyPI **0.1.9, 2024-05-06, stale vs GitHub main** | Yes (`SECURITY_DESCRIPTOR.from_bytes/to_bytes`) | Yes (`from_sddl`/`to_sddl`) | `IntFlag` enums | You supply the table |
| `impacket.ldap.ldaptypes` | Yes (`SR_SECURITY_DESCRIPTOR`, `ACCESS_ALLOWED_OBJECT_ACE`) | No | Raw `Mask` int | No |
| `bloodyAD` | Yes | Yes | Yes | Ships a GUID table |
| `pywin32` `win32security` | Yes | Yes | Partially | No |

Extended rights and property-set GUIDs (DCSync pair `1131f6aa-…`/`1131f6ad-…`, `User-Force-Change-Password`
`00299570-…`, `msDS-KeyCredentialLink`, `servicePrincipalName`): either hardcode ~30 GUIDs or enumerate
`CN=Extended-Rights,CN=Configuration,DC=…` (`rightsGuid`, `displayName`) and the schema
`attributeSecurityGUID` (~20 lines, demo-friendly).

### 1.3 Recommendation (Python-centric team)

Primary collector: `ldap3` (paged search 1000, LDAPS 636, NTLM bind with an ordinary domain account —
"standard-user assessment" is a selling point) + `winacl` pinned + `smbprotocol` for
`\\dc\SYSVOL\<domain>\Policies\*\{Machine,User}\Preferences\Groups\Groups.xml` and `GptTmpl.inf`.
`impacket` was the original choice for SMB but was dropped on 2026-09-23: Windows Defender quarantines
its `dcerpc/v5/dcomrt.py` during install (os error 225), and an offensive toolkit is not needed for file
reads. Alternative: `msldap` if the team is comfortable with asyncio.

PowerShell alternative: one `Export-ADSnapshot.ps1` (`ActiveDirectory` + `GroupPolicy` modules) emitting
the same JSON via `ConvertTo-Json -Depth 12`; wins on `Get-Acl AD:\` (named rights) and `Get-GPOReport`.

### 1.4 Collector-agnostic snapshot schema — five rules

1. `raw` vs `derived` split: adapters normalize; rules never string-match LDAP attribute names.
2. Stable identity = **objectGUID** (`object_id`); `object_sid` nullable (GPOs, templates, trusts, OUs
   have none). (Correction from feedback: the original draft keyed by objectSid.)
3. Canonical ACE-rights vocabulary (~15 tokens).
4. `coverage` map so a rule returns `not_assessed` instead of a false pass.
5. Findings are a separate store keyed `(rule_id, object_id, subject_id)` with lifecycle; trends fall out
   for free.

Adapters: `adsnap` (primary), then at most one importer (`sharphound_json` or `pingcastle_xml`) to prove
the claim. Two collectors prove it; three burn a build day.

**PingCastle licence caveat:** free Basic Edition is non-commercial; inclusion in a commercial
package/service needs a purchased licence. Fine for research/hackathons; never an embedded product feature.

## 2. Lab on Windows 11 Pro + Hyper-V

### 2.1 Media

| Item | Term | Notes |
|---|---|---|
| Windows Server 2022 ISO (Evaluation Center) | 180 days | Safest: seeding scripts are tested on it. Desktop Experience. |
| Windows Server 2025 ISO | 180 days | Newer; fine if 2022 unavailable. |
| Windows 11 Enterprise ISO | 90 days | Optional client. |
| `slmgr /rearm` | extends eval | Irrelevant for a 5-week project. |

### 2.2 Seeding tools

| Tool | Seeds | Requirements | Time | Fit |
|---|---|---|---|---|
| **vulnerable-AD** (WazeHell / safebuffer) | ACL/ACE abuse, Kerberoasting, AS-REP roasting, DnsAdmins, password in description, default passwords, sprayable accounts, DCSync rights, silver/golden prerequisites, SMB signing off; randomized | Run on the DC after AD DS; `Invoke-VulnAD -UsersLimit 100 -DomainName corp.local` | 5–10 min | Best single ROI. Does not seed ADCS ESC or GPP cpassword. |
| **BadBlood** (davidprowe) | Thousands of users/groups/computers/OUs + randomized ACLs (scale) | Run on DC | 15–45 min | Run before vulnerable-AD; stresses paged search. |
| **AutomatedLab** | Builds the lab: DC, members, ADCS role, clients, trusts, checkpoints | Hyper-V host + ISOs; PowerShell module | 30–60 min first run | The right builder for Hyper-V. |
| GOAD | Full attack surface, 2 forests / 3 domains, ADCS ESC1/2/3/4/8, delegation, MSSQL links | Vagrant + Ansible (Linux/WSL), no Hyper-V provider | Hours | Wrong shape; use its vuln list as reference. |
| Ludus | Wraps GOAD | Debian/Proxmox bare metal only | Hours | Disqualified. |
| DetectionLab | Detection stack | Vagrant/Packer | — | Unmaintained since 2023. |

### 2.3 Hardware

| VM | Role | vCPU | RAM (dynamic) | Disk |
|---|---|---|---|---|
| DC01 | WS2022 eval, AD DS + DNS | 2 | 2–4 GB | 60 GB dynamic VHDX |
| SRV01 | WS2022 eval, ADCS Enterprise CA + share | 2 | 2–4 GB | 60 GB |
| WS01 (optional) | Win11 Enterprise eval | 2 | 4 GB | 60 GB |

Floor: 16 GB RAM → DC01 only (or DC + SRV without client). Comfortable: 32 GB+. Use dynamic memory,
differencing disks off one sysprepped parent, Gen 2 VMs, an **Internal** switch (host gets an IP) plus a
temporary NAT switch during patching.

### 2.4 Topology and rebuild contract

```
Hyper-V Internal switch "LABNET" 10.10.10.0/24
  DC01  10.10.10.10   corp.local   AD DS, DNS
  SRV01 10.10.10.20   member       ADCS Enterprise CA, SMB share
  WS01  10.10.10.50   member       Win11 (optional)
  Host  10.10.10.1    dev box
```
Build: `01-Build-Lab.ps1` (AutomatedLab → checkpoint `clean`) → `02-BadBlood.ps1` → `03-VulnAD.ps1` →
`04-Seed-Extras.ps1` (ADCS ESC1/ESC2/ESC8, GPP cpassword Groups.xml, unconstrained delegation on SRV01,
RBCD, weak policy + unused FGPP, stale adminCount, PASSWD_NOTREQD, RC4-only, KeyCredentialLink write
for a non-Tier 0 workstation account, LAPS partial + readable → checkpoint `seeded`) → `05-Drift.ps1`
between scans. Seeds must not give the demo's start principal (helpdesk) a second route to Tier 0; the
designed path is defined in `lab/README.md`. Contract: restore `seeded` < 2 min; rebuild from `clean` < 20 min; from ISO < 60 min.
In-VM steps run from the host via PowerShell Direct (`Invoke-Command -VMName DC01`).

## 3. Stack versions (verified 2026-09-22)

| Component | Choice | Evidence |
|---|---|---|
| Python | 3.12 | 3.14 wheel gaps for AD libraries |
| Node.js | **24 LTS** (Active LTS until 2026-10-20, Maintenance to 2028-04-30) | Node 25 EOL 2026-06-01; Node 26 is Current (nodejs.org / nodejs/Release schedule.json) |
| React | **19.3.0** (2026-09-09) | react.dev/versions, npm dist-tag latest |
| winacl | 0.1.9 pinned (or a git commit) | PyPI; last release 2024-05-06 |
| ldap3 | ≥2.9.1 | paged search, controls |
| impacket | ≥0.12 | SMBConnection, ldaptypes |

## Sources

- ldap3 searches — https://ldap3.readthedocs.io/en/latest/searches.html
- msldap — https://github.com/skelsec/msldap · winacl — https://github.com/skelsec/winacl · PyPI — https://pypi.org/project/winacl/
- impacket — https://github.com/fortra/impacket (`impacket/ldap/ldaptypes.py`)
- bloodyAD — https://github.com/CravateRouge/bloodyAD
- MS-ADTS LDAP_SERVER_SD_FLAGS_OID — https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0 · default 0x0F — https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499 · extended access checks — https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e6685d31-5d87-42d0-8a5f-e55d337f47cd
- Get-GPOReport — https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gporeport
- SharpHound CE — https://github.com/SpecterOps/SharpHound · BloodHound.py — https://github.com/dirkjanm/BloodHound.py
- ADRecon — https://github.com/adrecon/ADRecon · PingCastle — https://www.pingcastle.com/download/
- Windows Server 2022 eval — https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022 · 2025 — https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025 · Win11 Enterprise — https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise
- vulnerable-AD — https://github.com/WazeHell/vulnerable-AD · BadBlood — https://github.com/davidprowe/BadBlood · AutomatedLab — https://github.com/AutomatedLab/AutomatedLab · GOAD — https://github.com/Orange-Cyberdefense/GOAD · Ludus — https://docs.ludus.cloud/docs/intro
- React versions — https://react.dev/versions · Node releases — https://nodejs.org/en/about/previous-releases · https://raw.githubusercontent.com/nodejs/Release/main/schedule.json

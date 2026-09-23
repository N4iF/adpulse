# AD security control assessment — check catalog (research, 2026-09-21)

Research output compiled from PingCastle rules, Semperis Purple Knight indicators, BloodHound edges,
Microsoft AD security guidance, ADSecurity.org, Certipy/Locksmith (ADCS), ANSSI and MITRE ATT&CK.
104 checks in 14 categories (90 standard-user, 10 elevated, 4 mixed). This is the long-term catalog;
product slices pick subsets. Severity and privilege are suggestions to be confirmed in the lab.

## Tier A — the 12 checks of the first product slice

All standard-user, all with public exploit tooling. Detection uses the derived fields defined in
`docs/architecture.md`; exclusions prevent false positives on a clean domain.

| ID | Sev | Detection (derived fields) | Exclusions / notes | ECC |
|---|---|---|---|---|
| DEL-01 | Critical | `unconstrained_delegation` and not `is_dc` | — | 2-2-3-4 |
| DEL-05 | High | domain `machine_account_quota` > 0 | — | 2-2-3-3 |
| ACL-01 | Critical | domain object ACE with `ExtendedRight:DS-Replication-Get-Changes` + `-All` (or `AllExtendedRights`/`GenericAll`) | trustee not in Tier 0 v1 | 2-2-3-3 |
| ACL-03 | Critical | ACE on a Tier 0 object with `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner` or `Owns` | trustee not in Tier 0 v1, not SELF/SYSTEM | 2-2-3-3 |
| PRV-04 | Critical | user with `kerberoastable` and (`admin_count` = 1 or member of Tier 0 v1) | not krbtgt (`is_builtin`), enabled only | 2-2-3-4 |
| KRB-01 | Critical | krbtgt `password_age_days` > threshold (default 180) | threshold is a documented parameter | 2-2-3-4 |
| KRB-02 | High | user `asrep_roastable` and `enabled` | — | 2-2-3-4 |
| KRB-03 | High | user `kerberoastable` and `enabled` | not krbtgt | 2-2-3-4 |
| PKI-01 | Critical | template `enrollee_supplies_subject` and `client_auth_eku` and not `requires_manager_approval` and `authorized_signatures` = 0 and `published_on_cas` non-empty and an enrollment ACE (`ExtendedRight:Certificate-Enrollment`/`-AutoEnrollment`, `GenericAll`) for a non-Tier 0 trustee | `not_assessed` when coverage `adcs` = none | 2-2-3-3 |
| GPO-01 | Critical | gpo `gpp_cpassword_files` non-empty | `not_assessed` when coverage `gpo_files` = none | 2-2-3-1 |
| ACC-01 | High | user `passwd_notreqd` and `enabled` | not built-in Guest (RID 501, disabled by default) | 2-2-3-1 |
| ACC-04 | High | user `password_in_text_indicator` | evidence = attribute names only, never values | 2-2-3-1 |

Designed lab path for the demo: `helpdesk —GenericWrite→ svc_sql —MemberOf→ Domain Admins`
(ACL-03 + PRV-04); the on-stage fix removes the GenericWrite ACE. See `lab/README.md`.

**Legend.** `Acc`: **U** = read-only LDAP/LDAPS bind as an ordinary domain user; **E** = elevated (DC local
admin / Domain Admin / delegated read on confidential attributes, remote registry, SACL read, DRSUAPI).
LDAP bit tests use the matching rule `1.2.840.113556.1.4.803` (bitwise AND). `Sev` = suggested severity.

## 1. Password & lockout policy

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| PWD-01 | Weak minimum password length | High | Domain NC root `minPwdLength` (<12) — `Get-ADDefaultDomainPasswordPolicy` | Brute-force / spray success — T1110.003 | Set >=14 | U |
| PWD-02 | Password complexity disabled | High | `pwdProperties` bit `0x1` (DOMAIN_PASSWORD_COMPLEX) not set | Trivially guessable passwords — T1110.001 | Enable complexity in Default Domain Policy | U |
| PWD-03 | Reversible encryption domain-wide | Critical | `pwdProperties` bit `0x10` (STORE_CLEARTEXT) set | Cleartext passwords in NTDS.dit — T1003.003 | Clear the flag, force reset all users | U |
| PWD-04 | No/weak account lockout | Medium | `lockoutThreshold`=0 or >10; `lockoutObservationWindow` short | Unlimited online guessing — T1110.003 | Threshold 5–10, window >=15 min | U |
| PWD-05 | Password never expires domain policy | Medium | `maxPwdAge`=0 (or `0x8000000000000000`) | Stale credentials persist — T1078.002 | Set 365 days max, or pair with MFA/long passphrase | U |
| PWD-06 | Weak / over-broad Fine-Grained Password Policy | High | `(objectClass=msDS-PasswordSettings)` under `CN=Password Settings Container,CN=System`; check `msDS-MinimumPasswordLength`, `msDS-PSOAppliesTo`, `msDS-PasswordSettingsPrecedence` | PSO silently weakens policy for admins — T1110 | Tighten PSO; never apply weak PSO to Tier 0 | E |

## 2. Accounts & credentials

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| ACC-01 | Accounts with PASSWD_NOTREQD | High | `(userAccountControl:1.2.840.113556.1.4.803:=32)` | Blank password logon — T1078.002 | Clear flag, force reset | U |
| ACC-02 | Password never expires (per-user) | Medium | UAC bit `65536` | Long-lived static creds — T1078.002 | Remove flag; move service accounts to gMSA | U |
| ACC-03 | Reversible encryption per-user | Critical | UAC bit `128` | Cleartext recovery from DC — T1003.003 | Clear flag + reset password | U |
| ACC-04 | Password in `description`/`info`/`comment` | High | `(\|(description=*pass*)(description=*pwd*)(info=*pass*))` — store a match indicator, never the value | Any user reads creds — T1552.001 | Purge attributes, rotate creds | U |
| ACC-05 | Built-in Administrator (RID 500) password stale | High | `(objectSid=*-500)` → `pwdLastSet` age >365d | Golden-ticket persistence / PtH — T1550.002 | Rotate, rename, disable interactive use | U |
| ACC-06 | Guest account enabled | Medium | `(objectSid=*-501)` and UAC bit `2` not set | Anonymous-ish foothold — T1078 | Disable Guest | U |
| ACC-07 | Service accounts with old passwords / no gMSA | High | `(&(servicePrincipalName=*)(objectCategory=user))` → `pwdLastSet` >365d; compare with `(objectClass=msDS-GroupManagedServiceAccount)` | Kerberoast offline crack — T1558.003 | Convert to gMSA/dMSA | U |
| ACC-08 | Accounts with SID History | High | `(sIDHistory=*)` — flag values resolving to privileged RIDs (512/518/519/544) | Hidden privilege / cross-domain escalation — T1134.005 | Remove sIDHistory after migration | U |
| ACC-09 | Shadow credentials present (`msDS-KeyCredentialLink`) | Critical | `(msDS-KeyCredentialLink=*)` on users/computers not enrolled in WHfB | Attacker-planted key → PKINIT as victim — T1556 | Delete rogue entries; audit write ACL on attribute | U |
| ACC-10 | Smart-card-required accounts with stale password hash | Medium | UAC bit `262144` + `pwdLastSet` very old | Static NT hash usable for PtH — T1550.002 | Toggle flag to force hash rotation | U |

## 3. Privileged access

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| PRV-01 | Excessive Domain/Enterprise/Schema Admins | High | Recursive membership of RIDs 512/519/518; count >5 / >0 for EA & SA steady state | Larger Tier 0 blast radius — T1078.002 | Empty EA/SA outside change windows; JIT membership | U |
| PRV-02 | Privileged accounts not in Protected Users | High | Members of Tier 0 groups absent from `Protected Users` (RID 525) | Creds cacheable/delegatable — T1550.002 | Add Tier 0 humans to Protected Users | U |
| PRV-03 | Privileged accounts delegatable | High | Tier 0 members without UAC bit `1048576` (NOT_DELEGATED) | Ticket theft via delegation — T1550.003 | Set "sensitive and cannot be delegated" | U |
| PRV-04 | Privileged accounts with SPNs (kerberoastable admins) | Critical | `(&(adminCount=1)(servicePrincipalName=*)(objectCategory=user))` | Offline crack → instant DA — T1558.003 | Remove SPN or convert to gMSA | U |
| PRV-05 | Stale `adminCount=1` orphans | Low | `(adminCount=1)` minus current Tier 0 membership | Inherits AdminSDHolder ACL, hides real ownership — T1098 | Reset adminCount, re-enable inheritance | U |
| PRV-06 | Non-empty legacy operator groups | High | Members of Account Operators (548), Backup Operators (551), Server Operators (549), Print Operators (550) | Each is a path to DC compromise — T1078.002 | Empty these groups | U |
| PRV-07 | DnsAdmins non-empty | High | `(sAMAccountName=DnsAdmins)` members | DLL load as SYSTEM on DC — T1543.003 | Empty group; treat as Tier 0 | U |
| PRV-08 | Privileged accounts stale / inactive | Medium | Tier 0 members with `lastLogonTimestamp` >90d | Forgotten, unmonitored DA accounts — T1078 | Disable/remove | U |
| PRV-09 | Cross-tier logon exposure | High | GPO `Deny log on locally/through RDP/as service/batch` for Tier 0 groups in `GptTmpl.inf` | Credential theft on Tier 2 host — T1003 | Tiered deny-logon GPOs + PAWs | U |
| PRV-10 | Privileged users revealed on an RODC | High | RODC `msDS-RevealedUsers`; `msDS-RevealOnDemandGroup` | RODC caches Tier 0 secrets — T1003.003 | Reset revealed accounts; add to Denied RODC Password Replication Group | U |
| PRV-11 | Group nesting from low-tier group into Tier 0 | High | Recursive `member`/`memberOf` expansion of Tier 0 groups; flag any group whose ACL is writable by non-Tier 0 | Silent privilege escalation path — T1098.007 | Flatten nesting; lock group ACLs | U |

## 4. Kerberos & authentication

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| KRB-01 | krbtgt password older than 180 days | Critical | `(sAMAccountName=krbtgt)` → `pwdLastSet` | Golden Ticket persistence — T1558.001 | Reset krbtgt twice, 10h+ apart | U |
| KRB-02 | AS-REP roastable accounts | High | `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` | Offline crack without any creds — T1558.004 | Enable Kerberos pre-auth | U |
| KRB-03 | Kerberoastable user accounts | High | `(&(objectCategory=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(UAC:…:=2)))` | Offline TGS crack — T1558.003 | gMSA, AES-only, 25+ char passwords | U |
| KRB-04 | RC4 / DES encryption permitted | High | `msDS-SupportedEncryptionTypes` absent, or bits `0x1/0x2/0x4` set without `0x18`; UAC bit `2097152` (DES only) | Cheap kerberoast + downgrade — T1558.003 | Set AES128+AES256 (`0x18`) domain-wide | U |
| KRB-05 | Long Kerberos ticket lifetimes | Low | `GptTmpl.inf` → `MaxTicketAge`, `MaxServiceAge`, `MaxRenewAge`, `MaxClockSkew` | Stolen tickets stay valid longer — T1550.003 | TGT 10h, renew 7d, skew 5m | U |
| KRB-06 | LM hash storage not disabled | High | GPO `NoLMHash` in `GptTmpl.inf` | Instantly crackable LM hashes — T1003.003 | Enable NoLMHash | U |
| KRB-07 | Weak `LmCompatibilityLevel` (<5) | High | GPO "LAN Manager authentication level" registry value | NTLMv1 relay/downgrade — T1557.001 | Set level 5 | U |
| KRB-08 | LDAP signing / channel binding not enforced on DCs | Critical | DC registry `LDAPServerIntegrity`=2 and `LdapEnforceChannelBinding`=2; or probe: simple bind over 389 succeeds unsigned | LDAP relay → object takeover — T1557.001 | Enforce signing + EPA on all DCs | E |
| KRB-09 | SMB signing not required on DCs | High | GPO "Digitally sign communications (always)"; or SMB negotiate probe | SMB relay to DC — T1557.001 | Require SMB signing everywhere | U/E |
| KRB-10 | Print Spooler running on DCs | High | RPC probe of `\pipe\spoolss`; or service state on DC | PrinterBug coerced auth → relay — T1187 | Disable Spooler on DCs | U |
| KRB-11 | Duplicate / suspicious SPNs | Low | Group `servicePrincipalName` values across all objects; flag duplicates and host-class SPNs on user objects | Silver ticket & service impersonation — T1558.002 | Deduplicate SPN registrations | U |

## 5. Delegation

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| DEL-01 | Unconstrained delegation on non-DC | Critical | `(&(userAccountControl:…:=524288)(!(primaryGroupID=516)))` on computers and users | Coerce DC auth → capture TGT → DA — T1187/T1550.003 | Remove; migrate to RBCD | U |
| DEL-02 | Constrained delegation with protocol transition | High | `msDS-AllowedToDelegateTo` populated **and** UAC bit `16777216` | S4U2Self→S4U2Proxy impersonation — T1134 | Drop protocol transition; scope targets | U |
| DEL-03 | Delegation targeting Tier 0 SPNs | Critical | `msDS-AllowedToDelegateTo` contains a DC/CIFS/LDAP/HOST SPN of a DC or Tier 0 host | Direct DC impersonation — T1550.003 | Remove delegation entry | U |
| DEL-04 | Resource-Based Constrained Delegation configured unexpectedly | High | `(msDS-AllowedToActOnBehalfOfOtherIdentity=*)`; decode SD, flag non-Tier 0 principals | Attacker-written RBCD → SYSTEM on target — T1134 | Clear attribute; restrict `WriteProperty` on it | U |
| DEL-05 | `ms-DS-MachineAccountQuota` > 0 | High | Domain NC root `ms-DS-MachineAccountQuota` | Any user creates a computer → RBCD/shadow-cred chains — T1136.002 | Set to 0; delegate machine-join to a group | U |
| DEL-06 | gMSA password retrievable by broad principals | Medium | `msDS-GroupMSAMembership` on gMSA objects | Non-owners read the gMSA password — T1555 | Restrict to the exact host/service group | U |

## 6. ACL / object permissions

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| ACL-01 | DCSync rights granted to non-Tier 0 | Critical | Domain NC root `ntSecurityDescriptor`: ACEs with ExtendedRight GUIDs `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`, `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`, `89e95b76-444d-4c62-991a-0facbeda640c` | Dump all hashes incl. krbtgt — T1003.006 | Remove ACE; keep only DCs + Administrators | U |
| ACL-02 | AdminSDHolder DACL modified | Critical | `CN=AdminSDHolder,CN=System,<domainDN>` `ntSecurityDescriptor` vs baseline | Backdoor auto-reapplied every 60 min — T1098 | Restore default ACL; alert on change | U |
| ACL-03 | GenericAll / WriteDacl / WriteOwner / GenericWrite on Tier 0 objects | Critical | Parse `ntSecurityDescriptor` of Tier 0 groups/users/computers for `0xF01FF`, `WRITE_DAC`, `WRITE_OWNER`, `0x20028` held by non-Tier 0 SIDs | Full object takeover — T1098 | Remove ACE; re-enable inheritance | U |
| ACL-04 | Non-default owner on privileged objects | High | Owner ≠ Domain Admins / Administrators | Owner implicitly gets WriteDacl — T1098 | Reset owner to Domain Admins; `dsHeuristics` Block-Owner-Implicit-Rights | U |
| ACL-05 | `User-Force-Change-Password` on admins | High | ExtendedRight GUID `00299570-246d-11d0-a768-00aa006e0529` in Tier 0 ACLs | Reset a DA password without knowing it — T1098 | Remove ACE | U |
| ACL-06 | Write on `msDS-KeyCredentialLink` / `servicePrincipalName` / `msDS-AllowedToActOnBehalfOfOtherIdentity` | High | Per-attribute WriteProperty ACEs (GUIDs `5b47d60f-…`, `f3a64788-…`, `3f78c3e5-…`) | Shadow credentials, targeted kerberoast, RBCD — T1556/T1558.003 | Strip attribute-level write for non-admins | U |
| ACL-07 | Dangerous rights on the Domain / DC OU / Configuration NC | Critical | ACL of `<domainDN>`, `OU=Domain Controllers`, `CN=Configuration` for non-Tier 0 write | GPO-link or object hijack of the whole domain — T1484.001 | Remove; restrict to Tier 0 | U |
| ACL-08 | Pre-Windows 2000 Compatible Access contains Authenticated Users/Everyone | Medium | Members of SID `S-1-5-32-554` | Broad directory read — T1087.002 | Empty the group | U |
| ACL-09 | Exchange/third-party groups with WriteDacl on domain | High | `Exchange Windows Permissions`, `Exchange Trusted Subsystem` ACEs on domain NC | Exchange admin → Domain Admin — T1098 | Split-permissions / remove inherited ACE | U |

## 7. Group Policy

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| GPO-01 | GPP `cpassword` in SYSVOL | Critical | Search `\\<domain>\SYSVOL\<domain>\Policies\**\*.xml` (Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml) for `cpassword=` — record presence only | AES key is public → instant local admin creds — T1552.006 | Delete XML, rotate passwords, use LAPS | U |
| GPO-02 | Non-admins can edit/link GPOs | Critical | `gPCFileSysPath` SYSVOL NTFS ACL + GPC `ntSecurityDescriptor`; `Group Policy Creator Owners` membership; `gPLink` write on OUs | Push SYSTEM code to every host — T1484.001 | Restrict GPO edit to Tier 0 | U |
| GPO-03 | GPO linked to Domain Controllers OU by non-Tier 0 | Critical | `gPLink` on `OU=Domain Controllers`; resolve each GPO's editors | DC code execution — T1484.001 | Remove link / fix GPO ACL | U |
| GPO-04 | Orphaned or version-mismatched GPOs | Low | GPC `versionNumber` vs `GPT.INI`; GPOs with no `gPLink` | Inconsistent/unenforced hardening | Repair or delete | U |
| GPO-05 | Startup/logon scripts on world-writable paths | High | Parse `Scripts.ini`/`psscripts.ini` in SYSVOL; check NTFS ACL of referenced UNC paths | Script replacement → mass code exec — T1574 | Move to SYSVOL with Tier 0 ACL | U |
| GPO-06 | Immediate/Scheduled Task GPP running as a privileged account | High | `ScheduledTasks.xml` `runAs` attribute | Credential exposure + privileged exec — T1053.005 | Remove; use gMSA | U |

## 8. Domain & forest configuration

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| DOM-01 | Domain/forest functional level below WS2016 | Medium | `msDS-Behavior-Version` on domain NC and `CN=Partitions,CN=Configuration` (<7) | No PAM/Protected Users/credential guard features — T1078 | Raise FFL/DFL to 2016+ | U |
| DOM-02 | Anonymous LDAP operations allowed | High | `dsHeuristics` on `CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration` — 7th char = `2` | Unauthenticated directory enumeration — T1087.002 | Set 7th char to `0` | U |
| DOM-03 | AD Recycle Bin disabled | Low | `msDS-EnabledFeature` on `CN=Partitions` lacks Recycle Bin GUID | Slow/incomplete recovery | Enable optional feature | U |
| DOM-04 | Non-default / shortened tombstone lifetime | Low | `tombstoneLifetime` on `CN=Directory Service` (<180) | Backup window shorter than detection window | Set 180 days | U |
| DOM-05 | No recent system-state backup of the DC | High | Replication metadata of `dSASignature` on domain NC root >30d | No forest recovery path — T1490 | Weekly system-state backup, offline copy | U |
| DOM-06 | Schema version out of date / unauthorized schema change | Medium | `objectVersion` on `CN=Schema,CN=Configuration`; `whenChanged` on schema objects | Missing security schema; schema backdoor — T1098 | Patch/extend schema; monitor schema writes | U |
| DOM-07 | Replication / DC health failures | Medium | `repadmin /showrepl`, `Get-ADReplicationFailure`; `dcdiag` | Stale ACL/policy on some DCs; possible rogue DC — T1207 | Fix replication; verify DC inventory | E |
| DOM-08 | Unexpected `nTDSDSA` objects (rogue DC) | Critical | `(objectClass=nTDSDSA)` under `CN=Sites,CN=Configuration` vs known DC list; `(userAccountControl:…:=8192)` | DCShadow / rogue replication — T1207 | Remove object; investigate | U |

## 9. Trusts

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| TRU-01 | SID filtering disabled on external/forest trust | Critical | `(objectClass=trustedDomain)` → `trustAttributes` lacking `0x4` (QUARANTINED_DOMAIN) / with `0x40` (TREAT_AS_EXTERNAL) | SID-history injection → DA — T1134.005 | Enable SID filtering | U |
| TRU-02 | Trust password older than 1 year | Medium | `trustedDomain` `whenChanged` / `pwdLastSet` on the TDO | Forged inter-realm TGT — T1558 | Rotate trust password | U |
| TRU-03 | SID history enabled across trust | High | `trustAttributes` bit `0x40`, plus `sIDHistory` values from the partner | Cross-forest privilege injection — T1134.005 | Disable SIDHistory on the trust | U |
| TRU-04 | Obsolete/unneeded or downlevel trust | Medium | `trustType`, `trustDirection`, `trustPartner`; NTLM-only or non-transitive legacy trusts | Unmanaged trust = unmanaged path — T1482 | Remove unused trusts | U |
| TRU-05 | Trust not using AES / selective authentication off | Medium | `msDS-SupportedEncryptionTypes` on TDO; `trustAttributes` bit `0x10` | RC4 downgrade; unrestricted cross-forest logon — T1558 | Enable AES + selective authentication | U |

## 10. ADCS / PKI

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| PKI-01 | ESC1 — requester-supplied SAN on auth template | Critical | Under `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration`: `msPKI-Certificate-Name-Flag & 0x1`, `pKIExtendedKeyUsage` contains client-auth/smartcard/PKINIT OID, `msPKI-Enrollment-Flag & 0x2`=0, `msPKI-RA-Signature`<1, Enroll ACE for broad group | Any user requests a cert as DA — T1649 | Clear ENROLLEE_SUPPLIES_SUBJECT or require manager approval | U |
| PKI-02 | ESC2/ESC3 — Any-Purpose or Enrollment Agent template | Critical | EKU `2.5.29.37.0` / empty EKU / `1.3.6.1.4.1.311.20.2.1` with broad enroll rights | Enroll-on-behalf-of any principal — T1649 | Restrict enrollment | U |
| PKI-03 | ESC4 — writable certificate template ACL | Critical | Template `nTSecurityDescriptor` with GenericAll/WriteDacl/WriteProperty for non-Tier 0 | Rewrite template into ESC1 — T1649 | Lock template ACLs | U |
| PKI-04 | ESC5 — weak ACL on PKI objects / CA host | Critical | ACLs of `CN=Public Key Services` subtree and the CA computer object | Full PKI takeover — T1649 | Restrict to Tier 0 | U |
| PKI-05 | ESC6 — `EDITF_ATTRIBUTESUBJECTALTNAME2` on CA | Critical | `certutil -config "<CA>" -getreg policy\EditFlags` (bit `0x00040000`) | SAN injection on any template — T1649 | Remove flag, restart CertSvc | E |
| PKI-06 | ESC7 — ManageCA / ManageCertificates to non-admins | Critical | `certutil -config "<CA>" -getreg CA\Security` | Enable ESC6 or approve own request — T1649 | Restrict CA roles | E |
| PKI-07 | ESC8 — web enrollment without HTTPS/EPA | Critical | `pKIEnrollmentService` `dNSHostName` → probe `http://<ca>/certsrv/` | NTLM relay of a DC → DA cert — T1187/T1649 | Disable web enrollment or enforce HTTPS + EPA | U |
| PKI-08 | ESC9/ESC10 — weak certificate binding | Critical | Template `msPKI-Enrollment-Flag & 0x80000`; DC registry `Kdc\StrongCertificateBindingEnforcement`<2 and `SCHANNEL\CertificateMappingMethods & 0x4` | Cert→account mapping hijack — T1649 | Set enforcement=2; clear UPN mapping bit | U + E |
| PKI-09 | ESC11 — `IF_ENFORCEENCRYPTICERTREQUEST` disabled | High | `certutil -config "<CA>" -getreg CA\InterfaceFlags` | Relay to CA RPC endpoint — T1187 | Enable flag | E |
| PKI-10 | ESC13 — issuance policy linked to a group | High | `(objectClass=msPKI-Enterprise-Oid)` under `CN=OID,CN=Public Key Services` with `msDS-OIDToGroupLink` | Certificate silently grants group membership — T1649 | Remove OID-to-group link | U |
| PKI-11 | ESC15/ESC16 — schema v1 app-policy abuse / disabled SID extension | Critical | `msPKI-Template-Schema-Version`=1 with client-auth use; CA `DisableExtensionList` containing `1.3.6.1.4.1.311.25.2` | Cert issued without SID extension → impersonation — T1649 | Patch CVE-2024-49019; remove OID from DisableExtensionList | U + E |
| PKI-12 | Untrusted/expiring certs in NTAuth store; weak CA key | High | `cACertificate` on `CN=NTAuthCertificates`; key size <2048, SHA-1, expiry | Forged smart-card logon; CA outage — T1649 | Prune NTAuth; reissue CA with RSA-3072/SHA-256 | U |

## 11. Stale objects & hygiene

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| STL-01 | Inactive user accounts | Medium | `lastLogonTimestamp` < now−180d and not disabled | Unmonitored spray/takeover targets — T1078.002 | Disable, then delete after 30d | U |
| STL-02 | Inactive computer accounts | Medium | `(objectCategory=computer)` `lastLogonTimestamp`/`pwdLastSet` < now−90d | Machine-account takeover, ghost hosts — T1078 | Disable and remove | U |
| STL-03 | Disabled accounts never cleaned up | Low | UAC bit `2` and `whenChanged` >1y | Directory bloat, re-enable risk | Delete per lifecycle policy | U |
| STL-04 | Users/computers in default `CN=Users` / `CN=Computers` containers | Low | `distinguishedName` ends in `CN=Users,<dn>` / `CN=Computers,<dn>` | No GPO applies → unhardened objects — T1078 | Redirect with `redirusr`/`redircmp` | U |
| STL-05 | Accounts with `pwdLastSet`=0 or never logged on | Medium | `pwdLastSet=0`, `lastLogon=0`, `logonCount=0` | Pre-staged accounts with known/blank passwords — T1078 | Remove or force set at first logon | U |
| STL-06 | Objects with hidden primary-group escalation | Medium | `primaryGroupID` = 512/516/518/519 on unexpected objects | Membership invisible in `member` — T1098.007 | Reset `primaryGroupID` to 513/515 | U |

## 12. Computers & OS versions

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| OS-01 | End-of-life server/client OS in domain | Critical | `operatingSystem`, `operatingSystemVersion` — flag <10.0.17763 / Win7/2008R2/2012R2 | Unpatched RCE — T1210 | Upgrade or isolate + ESU | U |
| OS-02 | DCs on unsupported OS | Critical | Same attrs filtered to `(primaryGroupID=516)` | Zerologon/PetitPotam class exposure — T1210 | Rebuild DCs on 2019/2022/2025 | U |
| OS-03 | Missing critical DC patches | Critical | `operatingSystemVersion` build vs KB baseline; netlogon RPC probe | Instant domain takeover — T1210/T1068 | Patch; enforce Netlogon secure RPC | U |
| OS-04 | Computer accounts with stale machine password | Medium | `pwdLastSet` >90d on enabled computers | Hash reuse / inactive but trusted host — T1078 | Rejoin or remove | U |
| OS-05 | Non-DC servers holding Tier 0 SPNs / admin agents | High | SPN inventory + members of local admins on DCs (GPO Restricted Groups) | Tier 0 dependency on a Tier 1 host — T1021.002 | Move agents/backup/monitoring to Tier 0 hosts | U |

Note: OS findings are findings about exposure; they are **not** patch-management compliance evidence
(ECC 2-3-3-3 is `not_assessed` unless host patch inventory is collected).

## 13. LAPS / local admin

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| LAP-01 | LAPS not deployed / schema absent | High | Schema search for `ms-Mcs-AdmPwd` or `msLAPS-Password`; count computers with expiration attributes vs total | Shared local admin password → lateral movement — T1078.003 | Deploy Windows LAPS | U |
| LAP-02 | LAPS password readable by non-Tier 0 | Critical | `ntSecurityDescriptor` of computer objects: ControlAccess/ReadProperty on the LAPS attribute set for unexpected SIDs | Any user reads local admin passwords — T1555 | Fix delegation | E |
| LAP-03 | LAPS expiration in the past / not rotating | Medium | `ms-Mcs-AdmPwdExpirationTime` < now | Password never rotated after use — T1078.003 | Enforce `PasswordAgeDays` <=30 | E |
| LAP-04 | Built-in local Administrator not disabled / no per-host uniqueness | High | GPO "Accounts: Administrator account status"; Restricted Groups in `GptTmpl.inf` | Pass-the-hash across all hosts — T1550.002 | Disable RID 500 or LAPS-manage it | U |

## 14. Auditing & logging

| ID | Name | Sev | Detect | Impact / ATT&CK | Fix | Acc |
|---|---|---|---|---|---|---|
| AUD-01 | Advanced audit subcategories not configured | High | `GptTmpl.inf` / `audit.csv` in DC GPO: Credential Validation, Kerberos Auth Service, Kerberos Service Ticket Ops, DS Access, Security Group Mgmt, Account Lockout | No telemetry for Kerberoast/DCSync — T1562.002 | Apply Microsoft audit baseline on DCs | U |
| AUD-02 | No SACL on domain root / AdminSDHolder / Tier 0 OUs | High | SACL portion of `ntSecurityDescriptor` (needs `SeSecurityPrivilege`) | ACL backdoors unlogged — T1562.002 | Audit ACEs for Everyone: Write/WriteDacl/WriteOwner | E |
| AUD-03 | PowerShell script-block / module logging disabled | Medium | GPO registry `EnableScriptBlockLogging`, `EnableModuleLogging`, `EnableTranscripting` | Fileless attacks invisible — T1562.002 | Enable all three | U |
| AUD-04 | Security event log too small / no forwarding | Medium | GPO `MaxSize` for Security log; WEF subscription / SIEM agent presence | Evidence rolls over — T1562.002 | 1–4 GB log, forward to SIEM | U/E |
| AUD-05 | No monitoring of Tier 0 group changes | High | SACL on Tier 0 groups + audit policy "Security Group Management" | Privilege escalation undetected — T1098 | Alert on 4728/4732/4756 for Tier 0 SIDs | E |

Note: audit findings are **not** event-log compliance evidence (ECC 2-12-3-x) unless log configuration is
actually collected; otherwise `not_assessed`.

**Total: 104 checks.** Build order for the first product slice: DEL-01, KRB-03, ACL-01 (vertical slice),
then PRV-04, KRB-01, KRB-02, PKI-01, GPO-01, DEL-05, ACC-01, ACL-03, ACC-04.

## Privilege split summary

- **Read-only LDAP as a plain domain user (90 of 104):** every `userAccountControl` bit test,
  SPN/delegation/SID-history/`msDS-KeyCredentialLink` enumeration, all `ntSecurityDescriptor` **DACL**
  reads (Authenticated Users hold `READ_CONTROL` on most objects by default), trust objects, certificate
  templates and PKI objects in the Configuration NC, functional levels, `dsHeuristics`,
  `ms-DS-MachineAccountQuota`, and **SYSVOL file reads** (GPP `cpassword`, `GptTmpl.inf`, scripts, audit CSVs).
- **Elevated required (10, plus 4 partly elevated):** LAPS password attributes (confidential-bit attributes), PSO objects,
  **SACL** reads (`SeSecurityPrivilege`), CA registry flags (ESC6/ESC7/ESC11/ESC16), DC KDC/SCHANNEL
  registry, DC service state and event-log config, replication health, DRSUAPI-based password quality.
- **Design note:** run the collector in both modes — a *standard-user* pass and a *privileged* pass — and
  show the coverage of each honestly.

## Scoring models of existing tools (for future research; not implemented in v1)

- **PingCastle:** four indicators (Stale Objects, Privileged Accounts, Trusts, Anomalies), each 0–100 from
  summed rule points (fixed, per-discovery with cap, or threshold-based), capped at 100; **Domain Risk =
  max** of the four (lower is better). Colour bands 0 / 1–10 / 10–30 / >30. Separate maturity level
  (ANSSI-based) and ATT&CK map.
- **Purple Knight:** ~190 IOEs/IOCs with severity; score as a percentage (higher is better) computed from
  failed indicators only, weighted by severity and object volume; category scores are independent metrics.
- **ADPulse v1 deliberately does not implement a domain score.** Prioritization uses documented factors
  and a labelled heuristic (see `architecture.md`). A category-scoring model can be researched later with
  the lab ground-truth dataset.

## Standard Tier 0 asset list

Tier 0 = every object with direct or indirect administrative control of the forest, its domains, or its
domain controllers, plus anything with control over those objects (transitive closure).

- **Groups (RID/SID):** Enterprise Admins (519), Schema Admins (518), Domain Admins (512),
  Administrators (S-1-5-32-544), Account Operators (548), Backup Operators (551), Server Operators (549),
  Print Operators (550), Domain Controllers (516), Read-only Domain Controllers (521), Enterprise
  Read-only Domain Controllers (498), Enterprise Domain Controllers (S-1-5-9), Key Admins (526),
  Enterprise Key Admins (527), Group Policy Creator Owners (520), Cert Publishers (517), DnsAdmins,
  Replicator, Incoming Forest Trust Builders, Pre-Windows 2000 Compatible Access (554) where populated.
- **Accounts:** built-in Administrator (RID 500), krbtgt (and per-RODC krbtgt), every DC computer
  account, AD Connect / Entra Connect sync accounts, ADFS service account + DKM container, CA service
  accounts, backup/EDR/monitoring service accounts that run on DCs.
- **Objects / containers:** the domain head, `CN=AdminSDHolder,CN=System`, `OU=Domain Controllers`,
  `CN=System`, Configuration and Schema NCs, `CN=Sites`, the `CN=Public Key Services` subtree, GPOs linked
  to the domain root or DC OU, SYSVOL, DNS zones.
- **Infrastructure:** DCs, AD CS / ADFS / Entra Connect servers, PAWs and jump servers, DC backup
  infrastructure, hypervisors hosting virtual DCs, DC-management agents.
- **Closure algorithm:** seed the set, unroll group membership recursively, then iteratively add any
  principal holding `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `WriteProperty` on a Tier 0
  attribute, `AllExtendedRights`, `ForceChangePassword`, or the DCSync extended-right pair, until the set
  stops growing. Any principal in the closure that is not a documented Tier 0 account is itself a finding.

## Sources

- PingCastle Health Check rules list — https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html
- PingCastle sample report (risk model & scoring text) — https://www.pingcastle.com/PingCastleFiles/ad_hc_test.mysmartlogon.com.html
- Purple Knight scoring — https://www.semperis.com/blog/pk-scoring-improves-understanding-of-identity-system-security-vulnerabilities/
- Purple Knight security indicators — https://www.semperis.com/purple-knight/security-indicators/
- BloodHound edges — https://bloodhound.specterops.io/resources/edges/overview · Tier Zero — https://bloodhound.specterops.io/get-started/security-boundaries/tier-zero-members
- Microsoft — Best practices for securing Active Directory — https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory
- Microsoft — AD DS Tier Model — https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model
- Certipy — https://github.com/ly4k/Certipy · ESC1–ESC16 wiki — https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation
- Locksmith — https://github.com/jakehildreth/Locksmith
- ADSecurity.org — https://adsecurity.org/
- ANSSI AD checklist — https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html
- MITRE ATT&CK: T1558.003, T1558.004, T1003.006, T1484.001, T1649, T1134.005, T1552.006, T1187 — https://attack.mitre.org/

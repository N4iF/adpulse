# NCA ECC-2:2024 — control text and evidence mapping (verified 2026-09-22)

**Official sources.** English PDF: https://cdn.nca.gov.sa/api/files/public/upload/86e09090-44e4-481f-bc28-355673607654_ECC--2024-EN.pdf
(56 pp., PDF generated 2025-07-27, linked from https://nca.gov.sa/en/regulatory-documents/controls-list/ecc/).
Arabic PDF (text layer, glyph mapping corrupted — transcribe from rendered pages, never text-extract):
https://cdn.nca.gov.sa/api/files/public/upload/29a9e86a-595f-4af9-8db5-88715a458a14_ECC-2-2024---NCA.pdf.

**Structure.** Five main domains: 1 Cybersecurity Governance · 2 Cybersecurity Defence · 3 Cybersecurity
Resilience · 4 Third-Party and Cloud Computing Cybersecurity · 5 Industrial Control Systems Cybersecurity.
Subdomains follow `x-y-1` define/document → `x-y-2` implement → `x-y-3` minimum requirements (the mapping
targets) → `x-y-4` periodic review. The document prints sub-controls with dots in the tables (`2.2.3.1`)
and with dashes in Appendix C (`2-2-3-1`); ADPulse uses dashes.

**Applicability and assessment (why ADPulse never claims compliance).** The document states: "Each
entity shall comply with all controls applicable thereto." and "The NCA shall evaluate the entities'
compliance with the ECC through multiple means, such as self-assessment by the entities, periodic reports
of the compliance tool, and/or field auditing visits…". ADPulse therefore reports **technical evidence**
per control, with a fixed limitation statement: *"This result evaluates technical AD configuration only;
organizational policy/process compliance is not assessed."*

## Subdomain 2-2 Identity and Access Management — verbatim English (MVP mapping targets)

| Control | Verbatim text (EN) | Arabic (normalized transcription; verify against rendered PDF) | Evidence from ADPulse checks |
|---|---|---|---|
| 2-2-3-1 | "Single-factor authentication based on username and password." | التحقق من الهوية أحادي العنصر بناءً على إدارة تسجيل المستخدم، وإدارة كلمة المرور | PWD-01…06, ACC-01, ACC-02, ACC-03, ACC-04, GPO-01 (technical evidence about the username/password authentication configuration) |
| 2-2-3-2 | "Multi-factor authentication, and defining the suitable authentication factors and their numbers as well as the suitable authentication techniques based on the result of impact assessment of authentication failure and bypass for remote access and for privileged accounts." | (transcribe) | Mostly `not_assessed` — AD alone cannot prove MFA. Partial evidence: smart-card-required flag on privileged accounts (ACC-10), Protected Users membership (PRV-02) |
| 2-2-3-3 | "User authorization based on identity and access control principles (Need-to-Know and Need-to-Use principle, Least Privilege principle, and Segregation of Duties principle)." | (transcribe) | ACL-01, ACL-03, ACL-04, ACL-05, ACL-06, ACL-07, DEL-05, PKI-01…04, GPO-02, LAP-02 |
| 2-2-3-4 | "Privileged access management." | إدارة الصلاحيات الهامة والحساسة | PRV-01…11, KRB-01, KRB-02, KRB-03, DEL-01…04, ACC-05, ACC-08 |
| 2-2-3-5 | "Periodic review of identities and access rights." | المراجعة الدورية لهويات الدخول والصلاحيات | The headline mapping: continuous periodic assessment is the mechanism; lifecycle history (new / resolved / regressed across scans) is the evidence; STL-01…06, PRV-05, PRV-08 |

Note the AR/EN divergence at 2-2-3-1: the Arabic edition reads "…based on user-registration management
and password management". Show both as printed.

## Controls that are `not_assessed` in the MVP (with the reason shown)

| Control | Verbatim text (EN) | Reason not assessed |
|---|---|---|
| 2-3-3-1 | "Protection from viruses, suspicious programs and activities, and malware on workstations and servers, using modern and advanced protection technologies and mechanisms, and securely managing them." | ADPulse does not collect endpoint protection state. |
| 2-3-3-2 | "Strict restriction on the use of external storage media and their security." | Out of scope. |
| **2-3-3-3** | **"Patch management for systems, applications, and devices."** | ADPulse currently does not collect host patch inventory. EOL OS (OS-01/02) is a finding, not patch-management evidence. (Correction: research draft said 2-3-3-2; the official document says 2-3-3-3.) |
| 2-3-3-4 | "Centralized clock synchronization with an accurate and trusted source, such as sources provided by the Saudi Standards, Metrology and Quality Organization (SASO)." | Out of scope. |
| 2-8 (Cryptography) | subdomain | Kerberos etype findings (KRB-04) are exposure findings; cryptographic policy compliance is not assessed. |
| 2-12-3-1 | "Activation of cybersecurity event logs for critical information assets within the entity." | Audit policy is only partially visible via GPO files; treat as `not_assessed` until audit configuration is collected. |
| 2-12-3-2 | "Activation of cybersecurity event logs for critical and privileged accounts accessing information assets as well as for remote access events within the entity." | Same. |
| 2-12-3-3 | "Identification of Security Information and Event Management (SIEM) techniques required for cybersecurity event logs collection." | Out of scope. |
| 2-12-3-4 | "Continuous monitoring of cybersecurity event logs." | Out of scope. |
| 2-12-3-5 | "Retention period of cybersecurity event logs (shall be at least 12 months)." | Out of scope. |

## Rule YAML mapping example

```yaml
id: DEL-01
severity: critical
privilege_required: standard
title_en: "Unconstrained Kerberos delegation on a non-domain-controller account"
title_ar: "تفويض Kerberos غير المقيّد على حساب ليس وحدة تحكم مجال"
why_it_matters_en: "This server can impersonate any employee, including executives and IT administrators."
why_it_matters_ar: "يستطيع هذا الخادم انتحال هوية أي موظف، بما في ذلك الإدارة التنفيذية ومسؤولي تقنية المعلومات."
remediation_en: "Remove unconstrained delegation; use resource-based constrained delegation; add privileged accounts to Protected Users."
remediation_ar: "أزل التفويض غير المقيّد؛ استخدم التفويض المقيّد القائم على المورد؛ أضف الحسابات ذات الصلاحيات إلى مجموعة Protected Users."
control_mappings:
  nca_ecc_2_2024: ["2-2-3-3", "2-2-3-4"]
attack_techniques: ["T1558", "T1550.003", "T1187"]
matches_pingcastle_rule: "P-UnconstrainedDelegation"
evidence_source: "userAccountControl TRUSTED_FOR_DELEGATION (0x80000) on non-DC objects"
assessment_limitation: "Evaluates technical AD configuration only; organizational policy/process compliance is not assessed."
```

## Rendered control-evidence example (UI / report)

```
ECC 2-2-3-3  User authorization … Least Privilege …
Technical evidence: FAIL
Evidence: 17 non-Tier-0 principals hold GenericAll/WriteDacl on Tier 0 objects (ACL-03); 2 principals hold DCSync rights (ACL-01).
Assessment limitation: This result evaluates technical AD configuration only; organizational policy/process compliance is not assessed.
```

## Other verified facts (2026-09-22)

- Node.js 25 is EOL (2026-06-01); Node 24 is Active LTS until 2026-10-20 then Maintenance LTS to
  2028-04-30; Node 26 is Current. React 19.3.0 released 2026-09-09. `winacl` 0.1.9 released 2024-05-06.
- LDAP_SERVER_SD_FLAGS_OID `1.2.840.113556.1.4.801`; control value `SEQUENCE { INTEGER flags }`; bits
  OWNER 0x1, GROUP 0x2, DACL 0x4, SACL 0x8; default 0x0F. (MS-ADTS 3.1.1.3.4.1.11, 6.1.3.2.)

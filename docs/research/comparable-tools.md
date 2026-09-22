# Comparable tools and positioning (research, 2026-09-21)

## Positioning table

| Tool | Cost | Cadence | Output | Audience | Where it stops |
|---|---|---|---|---|---|
| **PingCastle** (Netwrix) | Free Basic Edition for own use; Auditor/commercial licence to sell or embed | One-off scan (scriptable) | Static HTML + machine-readable XML; risk score 0–100 across Stale Objects / Privileged Accounts / Trusts / Anomalies; rules cite ANSSI + MITRE ATT&CK | Admin, with an exec summary page | No trend DB, no workflow, no NCA ECC/CIS/NIST mapping, English/French only |
| **Semperis Purple Knight** | Free community edition (email registration) | One-off scan | HTML/CSV/PDF, 200+ IoEs & IoCs, AD + Entra ID + Okta, scored by category | Admin + CISO | Closed source, point-in-time, no history, no regional framework mapping |
| **Semperis Forest Druid** | Free | One-off | Tier 0 attack-path GUI, "inside-out" from the privileged perimeter | AD architect | Tier 0 perimeter only; not a control assessment |
| **BloodHound CE** | Free, open source | Ingest-on-demand (Enterprise adds continuous) | Graph UI + Cypher | Red team, advanced blue team | Attack paths, not configuration controls; intimidating to management |
| **Microsoft Defender for Identity / Entra Secure Score** | Paid (M365 E5 or standalone) | Continuous, sensor on every DC | Portal, posture assessments in Secure Score, lateral-movement paths, alerts | SOC + management | Licensing + agent on DCs; cloud-tethered; Microsoft-framework mapping only |
| **Tenable Identity Exposure** (ex-Alsid) | Paid | Continuous, real-time | Dashboard, IoEs + IoAs | SOC + management | Enterprise price point; no NCA ECC mapping |
| **Netwrix / Quest** | Paid | Continuous auditing/change tracking | Dashboards, change reports, GPO versioning, recovery | Compliance + admin | Audit/change-focused, heavier deployment |
| **ADeleg** (mtth-bfft) | Free, open source | One-off | Delegation inventory (objects owned by users, ACEs, non-canonical ACLs, broken inheritance) | AD engineer | Delegation only; no report/scoring/trend |
| **Locksmith** (TrimarcJake) | Free, open source PS | One-off | ADCS ESC1–ESC8 finder and fixer | AD/PKI admin | ADCS only |
| **HardeningKitty** (scip AG) | Free, open source PS | One-off | Host OS config audit vs CIS/BSI/Microsoft baselines | Windows admin | Machine-level, not directory-level; complementary |
| **ADRecon** | Free, open source PS | One-off | CSV/Excel dump | Pentester/auditor | Raw data; no analysis, scoring or UI |
| ad-hoc `Invoke-ADSecurity`-style scripts | Free | Ad hoc | Console/CSV | Individual admin | No persistence, UI or trend |

## Our design differentiators

Stated as design choices, not as claims about the whole market:

- **Continuous finding lifecycle** — snapshot diffs with new / open / resolved / regressed and posture over time.
- **ECC evidence mapping** — each finding maps to NCA ECC-2:2024 controls as technical evidence, with
  explicit limitations.
- **Arabic + English output** — bilingual rule texts and RTL-correct reports.
- **Explicit coverage / not-assessed states** — the tool says what it could not see.
- **Evidence-backed potential privilege-escalation paths** — every edge carries evidence, preconditions
  and confidence.

**What we are not:** not an attack-path product (BloodHound does that better), not a one-off audit PDF
(PingCastle does that better). ADPulse is the continuous control-evidence layer that can sit on top of both.

## Compliance frameworks (for future mappings)

| Framework | AD-relevant anchors | Mapping availability |
|---|---|---|
| **NCA ECC-2:2024** (primary; see `nca-ecc-mapping.md`) | 2-2-3-1…5 IAM minimum requirements; 2-3-3-3 patch management; 2-8 cryptography; 2-12-3-1…5 event logs | Hand-written per rule |
| CIS Controls v8/v8.1 | 4 Secure Configuration, 5 Account Management (5.2, 5.3, 5.4), 6 Access Control (6.7, 6.8), 8 Audit Log Management; CIS Windows Server Benchmarks have a Domain Controller profile | CIS publishes cross-framework mappings |
| NIST CSF 2.0 | PR.AA-01…05, PR.PS, DE.CM-01/09, ID.AM, GV.RR | CIS ↔ CSF 2.0 mapping exists |
| MITRE ATT&CK | T1558.003, T1558.004, T1003.006, T1484.001, T1649, T1550 | PingCastle rules already cite ATT&CK ids |
| ANSSI AD checklist | `vuln1_adcs_template_auth_enroll_with_name`, `vuln2_delegation_t4d`, … | Cited in PingCastle rule docs |

## Sources

- Purple Knight — https://www.semperis.com/purple-knight/ · Forest Druid — https://www.semperis.com/forest-druid/
- Defender for Identity — https://learn.microsoft.com/en-us/defender-for-identity/what-is
- Tenable Identity Exposure — https://www.tenable.com/products/identity-exposure
- Netwrix PingCastle — https://netwrix.com/en/products/pingcastle/ · rules — https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html
- ADeleg — https://github.com/mtth-bfft/adeleg · Locksmith — https://github.com/TrimarcJake/Locksmith · HardeningKitty — https://github.com/scipag/HardeningKitty · ADRecon — https://github.com/adrecon/ADRecon
- CIS Controls v8 — https://www.cisecurity.org/controls/v8 · NIST CSF 2.0 — https://www.nist.gov/cyberframework · ANSSI — https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html

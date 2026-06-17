# BlackCat/ALPHV: LSASS Credential Harvesting Pre-Ransomware

**Hunt ID:** H-0033
**Date Created:** 2026-04-28
**Status:** Completed
**Analyst:** ir0n
**Source:** https://www.mandiant.com/resources/blog/blackcat-ransomware
**Platform:** CrowdStrike Falcon / Google SecOps SIEM
**ATT&CK Techniques:** T1003.001 — LSASS Memory, T1003.002 — Security Account Manager, T1555 — Credentials from Password Stores, T1110.003 — Password Spraying
**ATT&CK Tactics:** Credential Access
**Priority:** Critical

---

## LEARN — Threat Context

### Threat Summary
BlackCat/ALPHV affiliates harvest credentials early in the intrusion lifecycle using Mimikatz or custom LSASS dumpers before moving laterally. Intelligence indicates the group is actively targeting the financial and legal sectors. This hunt looks for LSASS access patterns and credential dumping tooling.

### MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic | Usage |
|-------------|----------------|--------|-------|
| T1003.001 | LSASS Memory | Credential Access | Mimikatz sekurlsa::logonpasswords |
| T1003.002 | Security Account Manager | Credential Access | reg save HKLM\SAM |
| T1555 | Credentials from Password Stores | Credential Access | Browser credential extraction |
| T1110.003 | Password Spraying | Credential Access | Distributed spray using harvested usernames |

---

## OBSERVE — Hypothesis Development

### Hunt Hypothesis
> "BlackCat affiliates operating in our environment are dumping LSASS credentials using Mimikatz or a custom dumper, observable as non-system processes opening lsass.exe with PROCESS_VM_READ access, or comsvcs.dll-based minidump creation."

---

## KEEP — Findings & Documentation

### Execution Log
| Field | Value |
|-------|-------|
| Date Executed | 2026-04-30 |
| Analyst | ir0n |
| Time Range Queried | 30 days |
| Total Rows Examined | 6,120 |
| Results Returned | 2 |
| Time to Complete | 2 hours |

### Findings
Both results were CrowdStrike sensor self-tests and legitimate AV product LSASS reads. No evidence of BlackCat tooling.

### Hunt Decision
- [x] **REJECT** — No evidence found
- [x] **SCHEDULE** — Recurring monthly

---

## METRICS — For Leadership Reporting

**Hunt Outcome:**
- [x] No Findings
- [ ] True Positive
- [ ] False Positive
- [ ] Inconclusive

**Threat Actor:**
- [ ] Scattered Spider
- [ ] Atlas Lion
- [ ] Other: BlackCat/ALPHV

**Converted to Detection Rule:**
- [x] No
- [ ] Yes — Platform: ___ | Rule Name: ___

**Converted to Hunting Rule:**
- [ ] No
- [x] Yes — Platform: CrowdStrike | Rule Name: LSASS — Non-System Process Memory Read

**Log/Visibility Gap Found:**
- [x] No
- [ ] Yes — Gap: ___

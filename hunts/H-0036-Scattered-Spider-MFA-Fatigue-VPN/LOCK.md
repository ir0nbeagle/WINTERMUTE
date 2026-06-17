# Scattered Spider: MFA Fatigue Attack Leading to VPN Compromise

**Hunt ID:** H-0036
**Date Created:** 2026-05-10
**Status:** Completed
**Analyst:** ir0n
**Source:** https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-243a
**Platform:** CrowdStrike Falcon / Google SecOps SIEM
**ATT&CK Techniques:** T1621 — Multi-Factor Authentication Request Generation, T1566.004 — Spearphishing Voice, T1078 — Valid Accounts, T1133 — External Remote Services, T1539 — Steal Web Session Cookie
**ATT&CK Tactics:** Initial Access, Credential Access, Persistence
**Priority:** Critical

---

## LEARN — Threat Context

### Threat Summary
Scattered Spider (UNC3944) employs MFA fatigue attacks combined with vishing to compromise VPN and SSO accounts. The actor calls helpdesk or the victim directly, impersonates IT staff, and pressures the victim to approve an MFA push or provide an OTP. Once authenticated, the actor registers a new MFA device for persistence and begins reconnaissance from inside the VPN.

### Threat Actor Profile
| Field | Details |
|-------|---------|
| **Name/Alias** | Scattered Spider / UNC3944 / Oktapus |
| **Type** | Cybercriminal |
| **Motivation** | Financial — ransomware, data extortion |
| **Target Industries** | Hospitality, retail, technology, telecommunications |
| **Geographic Focus** | US, UK |
| **Active Since** | 2022 |

### MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic | Usage |
|-------------|----------------|--------|-------|
| T1621 | MFA Request Generation | Credential Access | Flood user with push notifications until approved |
| T1566.004 | Spearphishing Voice | Initial Access | Vishing call to helpdesk or victim |
| T1078 | Valid Accounts | Defense Evasion | Uses stolen credentials from phishing kit |
| T1133 | External Remote Services | Persistence | VPN/Citrix access using compromised credentials |
| T1539 | Steal Web Session Cookie | Credential Access | EvilGinx2 proxy to capture session tokens |

---

## OBSERVE — Hypothesis Development

### Hunt Hypothesis
> "Scattered Spider has compromised a user's VPN credentials via MFA fatigue and is accessing internal systems from an IP not associated with the user's known locations, observable as a VPN authentication success event preceded by 5+ failed MFA push attempts, followed by authentication from a new IP geolocation."

---

## KEEP — Findings & Documentation

### Execution Log
| Field | Value |
|-------|-------|
| Date Executed | 2026-05-12 |
| Analyst | ir0n |
| Time Range Queried | 14 days |
| Total Rows Examined | 22,840 |
| Results Returned | 3 high-confidence hits |
| Time to Complete | 3.5 hours |

### Findings
| # | Description | Classification | Severity | Ticket/Case |
|---|-------------|---------------|----------|-------------|
| 1 | User account: 11 Okta push denials over 8 minutes, then approval from 185.220.x.x (Tor exit node) | True Positive | Critical | INC-2026-0601 |
| 2 | Same account: new MFA device registered 2 minutes after VPN login | True Positive | Critical | INC-2026-0601 |
| 3 | Account accessed internal Confluence and HR portal within 10 minutes of VPN login | True Positive | High | INC-2026-0601 |

### Hunt Decision
- [x] **ACCEPT** — Active Scattered Spider compromise confirmed, IR initiated

### Detection Automation
- [x] Yes — MFA push flood followed by approval → Detection rule
  - **Rule Name:** `SCATTERED-SPIDER — MFA Fatigue Success Pattern`
  - **Platform:** Google SecOps | Rule Name: SCATTERED-SPIDER — MFA Fatigue Success Pattern
  - **Estimated False Positive Rate:** Very Low

---

## METRICS — For Leadership Reporting

**Hunt Outcome:**
- [ ] No Findings
- [x] True Positive
- [ ] False Positive
- [ ] Inconclusive

**Threat Actor:**
- [x] Scattered Spider
- [ ] Atlas Lion
- [ ] Other: ___

**Converted to Detection Rule:**
- [ ] No
- [x] Yes — Platform: Google SecOps | Rule Name: SCATTERED-SPIDER — MFA Fatigue Success Pattern

**Converted to Hunting Rule:**
- [ ] No
- [x] Yes — Platform: CrowdStrike | Rule Name: SCATTERED-SPIDER — New MFA Device Post-VPN-Login

**Log/Visibility Gap Found:**
- [ ] No
- [x] Yes — Gap: No visibility into voice call metadata; vishing component cannot be detected through current telemetry

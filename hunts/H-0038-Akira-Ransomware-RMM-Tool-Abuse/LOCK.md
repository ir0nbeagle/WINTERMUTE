# Akira Ransomware: RMM Tool Abuse for Persistence and Lateral Movement

**Hunt ID:** H-0038
**Date Created:** 2026-05-20
**Status:** Completed
**Analyst:** ir0n
**Source:** https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a
**Platform:** CrowdStrike Falcon / Google SecOps SIEM
**ATT&CK Techniques:** T1219 — Remote Access Software, T1486 — Data Encrypted for Impact, T1490 — Inhibit System Recovery, T1112 — Modify Registry, T1562.001 — Disable or Modify Tools
**ATT&CK Tactics:** Command and Control, Impact, Defense Evasion
**Priority:** Critical

---

## LEARN — Threat Context

### Threat Summary
Akira ransomware affiliates abuse legitimate RMM tools (AnyDesk, Splashtop, Atera) for persistent access and lateral movement before deploying ransomware. The actor installs these tools silently using MSI packages or pre-existing vulnerabilities, uses them to move between systems, and disables endpoint security tools via registry modification before running the encryptor.

### Threat Actor Profile
| Field | Details |
|-------|---------|
| **Name/Alias** | Akira Ransomware |
| **Type** | Ransomware-as-a-Service |
| **Motivation** | Financial — ransom payments |
| **Target Industries** | Manufacturing, healthcare, education, SMB |
| **Geographic Focus** | North America, Europe |
| **Active Since** | March 2023 |

### MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic | Usage |
|-------------|----------------|--------|-------|
| T1219 | Remote Access Software | Command and Control | AnyDesk/Splashtop/Atera installed silently |
| T1486 | Data Encrypted for Impact | Impact | ChaCha20 encryption of files |
| T1490 | Inhibit System Recovery | Impact | Deletes VSS snapshots, disables Windows backup |
| T1112 | Modify Registry | Defense Evasion | Disables Windows Defender via registry keys |
| T1562.001 | Disable or Modify Tools | Defense Evasion | Kills AV processes before encryption |

---

## OBSERVE — Hypothesis Development

### Hunt Hypothesis
> "Akira affiliates have installed unauthorized RMM tools (AnyDesk, Splashtop, or Atera) on internal systems via silent MSI installation, using them as a persistent C2 channel before ransomware deployment, observable as RMM tool installation events from non-IT-admin accounts, followed by outbound connections to RMM relay infrastructure."

---

## KEEP — Findings & Documentation

### Execution Log
| Field | Value |
|-------|-------|
| Date Executed | 2026-05-22 |
| Analyst | ir0n |
| Time Range Queried | 14 days |
| Total Rows Examined | 18,750 |
| Results Returned | 4 suspicious |
| Time to Complete | 4 hours |

### Findings
| # | Description | Classification | Severity | Ticket/Case |
|---|-------------|---------------|----------|-------------|
| 1 | AnyDesk installed via msiexec on finance server from non-admin account at 02:14 AM | True Positive | Critical | INC-2026-0647 |
| 2 | AnyDesk outbound connection to anydesk.com relay from finance server — confirmed unauthorized | True Positive | Critical | INC-2026-0647 |
| 3 | Registry key HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware set to 1 on same host | True Positive | Critical | INC-2026-0647 |
| 4 | vssadmin delete shadows /all executed 40 minutes after AnyDesk install | True Positive | Critical | INC-2026-0647 |

### Hunt Decision
- [x] **ACCEPT** — Active Akira pre-ransomware activity found, IR initiated, host isolated

### Detection Automation
- [x] Yes — Unauthorized RMM install from non-admin account outside business hours → Detection rule
  - **Rule Name:** `AKIRA — Unauthorized RMM Installation`
  - **Platform:** CrowdStrike | Rule Name: AKIRA — Unauthorized RMM Installation
  - **Estimated False Positive Rate:** Low

### Lessons Learned
- **What worked well:** Time-of-day anomaly (2 AM install) was the key pivot
- **What to improve:** RMM tools should be application-allowlisted; any install outside approved list should auto-alert

---

## METRICS — For Leadership Reporting

**Hunt Outcome:**
- [ ] No Findings
- [x] True Positive
- [ ] False Positive
- [ ] Inconclusive

**Threat Actor:**
- [ ] Scattered Spider
- [ ] Atlas Lion
- [ ] Other: Akira Ransomware

**Converted to Detection Rule:**
- [ ] No
- [x] Yes — Platform: CrowdStrike | Rule Name: AKIRA — Unauthorized RMM Installation

**Converted to Hunting Rule:**
- [ ] No
- [x] Yes — Platform: CrowdStrike | Rule Name: AKIRA — RMM Outbound to Relay Infrastructure

**Log/Visibility Gap Found:**
- [ ] No
- [x] Yes — Gap: No application allowlist enforcement for RMM tools; any signed MSI can be installed silently

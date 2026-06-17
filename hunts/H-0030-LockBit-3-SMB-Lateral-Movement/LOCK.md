# LockBit 3.0: SMB-Based Lateral Movement Pre-Encryption

**Hunt ID:** H-0030
**Date Created:** 2026-04-08
**Status:** Completed
**Analyst:** ir0n
**Source:** https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a
**Platform:** CrowdStrike Falcon / Google SecOps SIEM
**ATT&CK Techniques:** T1021.002 — SMB/Windows Admin Shares, T1570 — Lateral Tool Transfer, T1486 — Data Encrypted for Impact, T1490 — Inhibit System Recovery, T1562.001 — Disable or Modify Tools
**ATT&CK Tactics:** Lateral Movement, Impact, Defense Evasion
**Priority:** Critical

---

## LEARN — Threat Context

### Threat Summary
LockBit 3.0 affiliates use legitimate Windows SMB functionality to move laterally before deploying ransomware. The affiliate authenticates with harvested credentials, copies the LockBit payload to admin shares (C$, ADMIN$), and executes remotely via PsExec or sc.exe. Prior to encryption, VSS snapshots are deleted and AV/EDR processes are terminated via a dedicated killer script.

### Threat Actor Profile
| Field | Details |
|-------|---------|
| **Name/Alias** | LockBit 3.0 (affiliates) |
| **Type** | Ransomware-as-a-Service |
| **Motivation** | Financial — ransom payments |
| **Target Industries** | Healthcare, manufacturing, legal, government |
| **Geographic Focus** | Global |
| **Active Since** | 2019 (3.0 since 2022) |

### MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic | Usage |
|-------------|----------------|--------|-------|
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | Copies payload to C$ / ADMIN$ shares |
| T1570 | Lateral Tool Transfer | Lateral Movement | PsExec used to push and execute payload |
| T1486 | Data Encrypted for Impact | Impact | AES-256 + RSA encryption of files |
| T1490 | Inhibit System Recovery | Impact | vssadmin delete shadows /all |
| T1562.001 | Disable or Modify Tools | Defense Evasion | Kills AV/EDR processes before encryption |

---

## OBSERVE — Hypothesis Development

### Hunt Hypothesis
> "LockBit affiliates operating in our environment are using SMB admin shares and PsExec for lateral movement prior to ransomware deployment, observable as a single host making sequential SMB connections to multiple internal hosts on port 445, followed by remote service creation events."

---

## CHECK — Query Execution Plan

### Required Data Sources
| Data Source | Platform | Key Fields |
|------------|---------|------------|
| Network Events | CrowdStrike | RemotePort=445, ImageFileName |
| Process Events | CrowdStrike | CommandLine containing vssadmin, PsExec |
| Service Events | CrowdStrike | ServiceName, ImagePath |

---

## KEEP — Findings & Documentation

### Execution Log
| Field | Value |
|-------|-------|
| Date Executed | 2026-04-10 |
| Analyst | ir0n |
| Time Range Queried | 30 days |
| Total Rows Examined | 12,440 |
| Results Returned | 0 suspicious |
| Time to Complete | 3 hours |

### Findings
No evidence of LockBit lateral movement patterns. SMB activity observed was consistent with legitimate IT operations (patch deployment, backup agents).

### Hunt Decision
- [x] **REJECT** — No evidence found in this environment/time window
- [x] **SCHEDULE** — Schedule as recurring hunt (monthly)

### Lessons Learned
- **What worked well:** Baselining SMB activity first reduced false positives significantly
- **Visibility gaps found:** No visibility into SMB file copy operations — only connection events available

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
- [ ] Other: ___

**Converted to Detection Rule:**
- [x] No
- [ ] Yes — Platform: ___ | Rule Name: ___

**Converted to Hunting Rule:**
- [ ] No
- [x] Yes — Platform: CrowdStrike | Rule Name: LockBit — SMB Fan-Out Pattern

**Log/Visibility Gap Found:**
- [ ] No
- [x] Yes — Gap: No visibility into SMB file copy content or PsExec remote execution command line on target hosts

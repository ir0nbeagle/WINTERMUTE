# Insider Threat: Data Staging and Exfiltration Prior to Resignation

**Hunt ID:** H-0031
**Date Created:** 2026-04-15
**Status:** Completed
**Analyst:** ir0n
**Source:** Internal HR tip — employee submitted resignation notice
**Platform:** CrowdStrike Falcon / Google SecOps SIEM
**ATT&CK Techniques:** T1074.001 — Local Data Staging, T1560.001 — Archive via Utility, T1567.002 — Exfiltration to Cloud Storage, T1048.003 — Exfiltration over Unencrypted Protocol, T1078 — Valid Accounts
**ATT&CK Tactics:** Collection, Exfiltration, Defense Evasion
**Priority:** High

---

## LEARN — Threat Context

### Threat Summary
Insider threat hunt triggered by an HR notification of a resignation from a senior engineer with access to source code repositories, customer data, and internal tooling. Pattern of interest: data staging (large archive creation), followed by upload to personal cloud storage. This is a behavioral hunt — no external threat actor, focus is on detecting policy violations and potential IP theft before the employee's last day.

### Threat Actor Profile
| Field | Details |
|-------|---------|
| **Name/Alias** | Insider — Departing Employee |
| **Type** | Insider Threat (unintentional or malicious) |
| **Motivation** | Potential IP theft, competitive advantage at new employer |
| **Target** | Source code, customer PII, internal documentation |
| **Risk Window** | Notice period (2 weeks from 2026-04-15) |

### MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic | Usage |
|-------------|----------------|--------|-------|
| T1074.001 | Local Data Staging | Collection | Large ZIP/tar archives created on personal directories |
| T1560.001 | Archive via Utility | Collection | 7-Zip, tar, zip used to compress sensitive directories |
| T1567.002 | Exfiltration to Cloud Storage | Exfiltration | Upload to Dropbox, Google Drive, OneDrive personal accounts |
| T1048.003 | Exfiltration over Unencrypted Protocol | Exfiltration | HTTP PUT/POST to cloud storage APIs |
| T1078 | Valid Accounts | Defense Evasion | Using own valid credentials — appears legitimate |

---

## OBSERVE — Hypothesis Development

### Hunt Hypothesis
> "The departing employee is staging sensitive data by creating large archives of source code or customer data directories and uploading them to personal cloud storage, observable as 7-Zip or native archive utilities creating large files in non-standard directories, followed by outbound HTTP/S transfers to Dropbox, Google Drive, or similar personal storage endpoints from the employee's endpoint."

---

## CHECK — Query Execution Plan

### Required Data Sources
| Data Source | Platform | Key Fields |
|------------|---------|------------|
| File Events | CrowdStrike | TargetFileName, ImageFileName, FileSize |
| Network Events | CrowdStrike | DomainName, BytesSent, ImageFileName |
| Process Events | CrowdStrike | CommandLine, UserName |

---

## KEEP — Findings & Documentation

### Execution Log
| Field | Value |
|-------|-------|
| Date Executed | 2026-04-16 |
| Analyst | ir0n |
| Time Range Queried | 30 days |
| Total Rows Examined | 8,203 |
| Results Returned | 14 suspicious events |
| Time to Complete | 4 hours |

### Findings
| # | Description | Classification | Severity | Ticket/Case |
|---|-------------|---------------|----------|-------------|
| 1 | Employee created 3 ZIP archives >500MB in C:\Users\[user]\Downloads — contents include /repos/customer-api and /data/pii-export | True Positive | Critical | INC-2026-0512 |
| 2 | Outbound transfer of 1.2GB to dropbox.com from employee workstation over 4 hours | True Positive | Critical | INC-2026-0512 |
| 3 | 7z.exe used to archive C:\repos\internal-tools directory | True Positive | High | INC-2026-0512 |

### Hunt Decision
- [x] **ACCEPT** — Evidence of insider data staging found, escalated to HR and Legal

### Detection Automation
- [x] Yes — Archive utility creating >200MB file in user Downloads/Desktop → Detection rule
  - **Rule Name:** `INSIDER — Large Archive Creation in User Directory`
  - **Platform:** CrowdStrike | Rule Name: INSIDER — Large Archive Creation in User Directory
  - **Estimated False Positive Rate:** Medium (developers legitimately archive large projects)

### Lessons Learned
- **What worked well:** Combining file size thresholds with cloud storage destinations was high signal
- **Visibility gaps found:** Cannot inspect archive contents to confirm what was staged

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
- [x] Other: Insider — Departing Employee

**Converted to Detection Rule:**
- [ ] No
- [x] Yes — Platform: CrowdStrike | Rule Name: INSIDER — Large Archive Creation in User Directory

**Converted to Hunting Rule:**
- [ ] No
- [x] Yes — Platform: CrowdStrike | Rule Name: INSIDER — Cloud Storage Bulk Upload

**Log/Visibility Gap Found:**
- [ ] No
- [x] Yes — Gap: Cannot inspect archive contents at creation time; DLP tooling would provide content-level visibility

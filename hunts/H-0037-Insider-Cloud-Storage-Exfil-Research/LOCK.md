# Insider Threat: Unauthorized Cloud Storage Exfiltration by Research Staff

**Hunt ID:** H-0037
**Date Created:** 2026-05-14
**Status:** Completed
**Analyst:** ir0n
**Source:** DLP alert — blocked upload attempt to unauthorized cloud storage
**Platform:** CrowdStrike Falcon / Google SecOps SIEM
**ATT&CK Techniques:** T1567.002 — Exfiltration to Cloud Storage, T1048.003 — Exfiltration over Unencrypted Protocol, T1530 — Data from Cloud Storage
**ATT&CK Tactics:** Exfiltration, Collection
**Priority:** Medium

---

## LEARN — Threat Context

### Threat Summary
DLP system flagged a blocked upload attempt from a research department endpoint to a personal Mega.nz account. Hunt scope: determine if the upload was isolated or part of a broader pattern, identify what data was involved, and determine whether any prior successful uploads occurred before DLP was enabled on this endpoint class.

### MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic | Usage |
|-------------|----------------|--------|-------|
| T1567.002 | Exfiltration to Cloud Storage | Exfiltration | Upload to Mega.nz personal account |
| T1048.003 | Exfiltration over Unencrypted Protocol | Exfiltration | HTTP upload (not inspected prior to DLP) |
| T1530 | Data from Cloud Storage | Collection | Accessing internal S3 buckets before staging |

---

## OBSERVE — Hypothesis Development

### Hunt Hypothesis
> "A research staff member is exfiltrating intellectual property to personal cloud storage, with uploads to Mega.nz that pre-date the DLP policy being enabled on research endpoints, observable in network logs as HTTPS connections to mega.nz from research VLAN hosts with significant data transfer volumes."

---

## KEEP — Findings & Documentation

### Execution Log
| Field | Value |
|-------|-------|
| Date Executed | 2026-05-15 |
| Analyst | ir0n |
| Time Range Queried | 90 days |
| Total Rows Examined | 9,330 |
| Results Returned | 0 pre-DLP uploads |
| Time to Complete | 2 hours |

### Findings
No evidence of successful uploads prior to DLP enablement. The blocked upload was an isolated attempt. Network logs show no prior Mega.nz connections from research VLAN. The upload was a personal file unrelated to company data — employee confirmation obtained.

### Hunt Decision
- [x] **REJECT** — No evidence of IP theft; isolated DLP alert explained

### Lessons Learned
- **What worked well:** DLP caught the attempt; network logs provided historical context
- **What to improve:** Research VLAN should have been under DLP coverage earlier

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
- [x] Other: Insider — Research Staff (No Malicious Intent Confirmed)

**Converted to Detection Rule:**
- [x] No
- [ ] Yes — Platform: ___ | Rule Name: ___

**Converted to Hunting Rule:**
- [x] No
- [ ] Yes — Platform: ___ | Rule Name: ___

**Log/Visibility Gap Found:**
- [ ] No
- [x] Yes — Gap: Research endpoints were not under DLP coverage for 90 days prior to the alert; historical uploads undetectable

# Insider Threat: Excessive OAuth Token Generation by Departing Employee

**Hunt ID:** H-0034
**Date Created:** 2026-05-01
**Status:** Completed
**Analyst:** ir0n
**Source:** Okta anomaly alert — excessive token generation
**Platform:** CrowdStrike Falcon / Google SecOps SIEM
**ATT&CK Techniques:** T1528 — Steal Application Access Token, T1550.001 — Application Access Token, T1078 — Valid Accounts
**ATT&CK Tactics:** Credential Access, Defense Evasion, Lateral Movement
**Priority:** High

---

## LEARN — Threat Context

### Threat Summary
Okta flagged a spike in OAuth token generation for a user account belonging to a contractor whose engagement ended the prior week. Initial concern was the contractor generating long-lived tokens to retain access post-offboarding. Hunt scope: determine if tokens were generated maliciously, what resources were accessed, and whether any tokens remain active.

### MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic | Usage |
|-------------|----------------|--------|-------|
| T1528 | Steal Application Access Token | Credential Access | Creating OAuth tokens for persistent access |
| T1550.001 | Application Access Token | Defense Evasion | Using tokens to bypass MFA post-offboarding |
| T1078 | Valid Accounts | Defense Evasion | Contractor account not yet deprovisioned |

---

## OBSERVE — Hypothesis Development

### Hunt Hypothesis
> "A contractor whose engagement ended is generating OAuth tokens to maintain access to internal SaaS applications post-offboarding, observable as token generation events in Okta logs from an account that should be deprovisioned, from an IP not associated with company VPN."

---

## KEEP — Findings & Documentation

### Execution Log
| Field | Value |
|-------|-------|
| Date Executed | 2026-05-02 |
| Analyst | ir0n |
| Time Range Queried | 14 days |
| Total Rows Examined | 3,412 |
| Results Returned | 47 token events |
| Time to Complete | 1.5 hours |

### Findings
Token generation spike was caused by a misconfigured CI/CD pipeline that used the contractor's service account credentials. No evidence of malicious activity — the contractor's personal device was not involved. Pipeline was reconfigured to use a dedicated service account.

### Hunt Decision
- [x] **REJECT** — False positive; CI/CD misconfiguration

### Lessons Learned
- **What worked well:** Okta log correlation identified the source quickly
- **What to improve:** Service accounts should not be tied to individual contractor identities

---

## METRICS — For Leadership Reporting

**Hunt Outcome:**
- [ ] No Findings
- [ ] True Positive
- [x] False Positive
- [ ] Inconclusive

**Threat Actor:**
- [ ] Scattered Spider
- [ ] Atlas Lion
- [x] Other: Insider — Contractor (False Positive)

**Converted to Detection Rule:**
- [x] No
- [ ] Yes — Platform: ___ | Rule Name: ___

**Converted to Hunting Rule:**
- [x] No
- [ ] Yes — Platform: ___ | Rule Name: ___

**Log/Visibility Gap Found:**
- [ ] No
- [x] Yes — Gap: Service accounts tied to individual user identities make attribution difficult; no automated deprovisioning of contractor service accounts on engagement end

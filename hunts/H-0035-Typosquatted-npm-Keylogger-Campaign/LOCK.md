# Supply Chain: Typosquatted npm Packages with Embedded Keylogger

**Hunt ID:** H-0035
**Date Created:** 2026-05-06
**Status:** Active
**Analyst:** ir0n
**Source:** https://socket.dev/blog/npm-typosquat-keylogger-2026
**Platform:** CrowdStrike Falcon / Google SecOps SIEM
**ATT&CK Techniques:** T1195.001 — Supply Chain Compromise, T1056.001 — Keylogging, T1041 — Exfiltration Over C2 Channel, T1027 — Obfuscated Files or Information
**ATT&CK Tactics:** Initial Access, Collection, Exfiltration, Defense Evasion
**Priority:** High

---

## LEARN — Threat Context

### Threat Summary
An unattributed threat actor published 23 typosquatted npm packages mimicking popular React, Express, and testing libraries (e.g., reakt, expresss, jestjs). Packages install a persistent keylogger via a postinstall hook that hooks Node.js stdin and sends keystrokes to a remote endpoint every 60 seconds. Targeted at web developers with access to production deployment credentials.

### MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic | Usage |
|-------------|----------------|--------|-------|
| T1195.001 | Supply Chain Compromise | Initial Access | Typosquatted npm packages |
| T1056.001 | Keylogging | Collection | Node.js stdin hook captures all terminal input |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Keystroke batches sent via HTTPS every 60s |
| T1027 | Obfuscated Files or Information | Defense Evasion | Base64-encoded payload in package.json scripts |

---

## OBSERVE — Hypothesis Development

### Hunt Hypothesis
> "Developer endpoints with typosquatted npm packages installed have a persistent Node.js process running that sends periodic outbound HTTPS requests to attacker infrastructure every ~60 seconds, observable as a long-running node process with consistent periodic network connections to a non-CDN external IP."

---

## KEEP — Findings & Documentation

### Execution Log
| Field | Value |
|-------|-------|
| Date Executed | — |
| Analyst | — |
| Time Range Queried | — |
| Total Rows Examined | — |
| Results Returned | — |
| Time to Complete | — |

### Hunt Decision
- [ ] **ACCEPT**
- [ ] **REJECT**
- [ ] **REFINE**
- [ ] **SCHEDULE**

---

## METRICS — For Leadership Reporting

**Hunt Outcome:**
- [ ] No Findings
- [ ] True Positive
- [ ] False Positive
- [ ] Inconclusive

**Threat Actor:**
- [ ] Scattered Spider
- [ ] Atlas Lion
- [ ] Other: Unknown — npm typosquat actor

**Converted to Detection Rule:**
- [x] No
- [ ] Yes — Platform: ___ | Rule Name: ___

**Converted to Hunting Rule:**
- [x] No
- [ ] Yes — Platform: ___ | Rule Name: ___

**Log/Visibility Gap Found:**
- [x] No
- [ ] Yes — Gap: ___

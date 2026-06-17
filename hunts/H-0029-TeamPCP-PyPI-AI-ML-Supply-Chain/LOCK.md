# TeamPCP: Malicious PyPI Packages Targeting AI/ML Ecosystem

**Hunt ID:** H-0029
**Date Created:** 2026-04-02
**Status:** Completed
**Analyst:** ir0n
**Source:** https://blog.phylum.io/teamPCP-targets-ai-ml-pypi
**Platform:** CrowdStrike Falcon / Google SecOps SIEM
**ATT&CK Techniques:** T1195.001 — Supply Chain Compromise, T1059.006 — Python, T1552 — Unsecured Credentials, T1071.001 — Application Layer Protocol: Web, T1041 — Exfiltration Over C2 Channel
**ATT&CK Tactics:** Initial Access, Execution, Credential Access, Exfiltration
**Priority:** Critical

---

## LEARN — Threat Context

### Threat Summary
TeamPCP published malicious packages to PyPI targeting the AI/ML developer ecosystem. Packages mimicked popular ML libraries (torch-utils-ext, sklearn-accelerate, huggingface-hub-fast) and executed a post-install hook that harvested API keys for OpenAI, Anthropic, HuggingFace, and AWS from environment variables and config files, exfiltrating them to a TeamPCP-controlled endpoint.

### Threat Actor Profile
| Field | Details |
|-------|---------|
| **Name/Alias** | TeamPCP / @pcpcats |
| **Type** | Cybercriminal |
| **Motivation** | Financial — API key theft for resale, LLM credit abuse |
| **Target Industries** | AI/ML research, software development, data science |
| **Geographic Focus** | Global |
| **Active Since** | September 2025 |

### MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic | Usage |
|-------------|----------------|--------|-------|
| T1195.001 | Supply Chain Compromise: Software Dependencies | Initial Access | Malicious PyPI packages with typosquatted names |
| T1059.006 | Python | Execution | setup.py post-install hook executes payload |
| T1552 | Unsecured Credentials | Credential Access | Harvests API keys from env vars and ~/.config files |
| T1071.001 | Application Layer Protocol: Web | C2 | Exfil to HTTPS endpoint masquerading as telemetry |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | API keys sent in HTTP POST body |

---

## OBSERVE — Hypothesis Development

### Hunt Hypothesis
> "TeamPCP malicious PyPI packages are executing on data science and ML engineering endpoints via post-install hooks, observable as Python processes spawning immediately after pip install and making outbound HTTPS connections to non-PyPI endpoints, followed by reads of environment variable files and AI provider config directories."

### What Suspicious Looks Like
- `pip` spawning child Python process that immediately makes outbound HTTPS to non-registry endpoints
- Python reading `~/.config/anthropic`, `~/.openai`, `~/.aws/credentials` during or after package install
- `setup.py` or `__init__.py` containing encoded strings and `requests.post()` calls

---

## CHECK — Query Execution Plan

### Required Data Sources
| Data Source | Platform | Key Fields |
|------------|---------|------------|
| Process Events | CrowdStrike | FileName, CommandLine, ParentBaseFileName |
| Network Events | CrowdStrike | RemoteIP, DomainName, ImageFileName |
| File Events | CrowdStrike | TargetFileName, ImageFileName |

---

## KEEP — Findings & Documentation

### Execution Log
| Field | Value |
|-------|-------|
| Date Executed | 2026-04-05 |
| Analyst | ir0n |
| Time Range Queried | 14 days |
| Total Rows Examined | 4,821 |
| Results Returned | 7 |
| Time to Complete | 2.5 hours |

### Findings
| # | Description | Classification | Severity | Ticket/Case |
|---|-------------|---------------|----------|-------------|
| 1 | ML engineer workstation: pip spawning python child with outbound POST to 104.21.77.42 immediately after torch-utils-ext install | True Positive | High | INC-2026-0441 |
| 2 | Same host: python.exe read ~/.config/anthropic/api_key 30 seconds after install | True Positive | High | INC-2026-0441 |

### Hunt Decision
- [x] **ACCEPT** — Evidence of TeamPCP PyPI activity found, proceed to IR

### Detection Automation
- [ ] Pip spawning Python child with immediate outbound non-registry connection → Detection rule
  - **Rule Name:** `TEAMPC — pip Post-Install Outbound Connection`
  - **Platform:** CrowdStrike
  - **Estimated False Positive Rate:** Low

### Lessons Learned
- **What worked well:** DNS telemetry caught the C2 callback quickly
- **Visibility gaps found:** No visibility into PyPI package content at install time

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
- [x] TeamPCP
- [ ] Other: ___

**Converted to Detection Rule:**
- [ ] No
- [x] Yes — Platform: CrowdStrike | Rule Name: TEAMPC — pip Post-Install Outbound Connection

**Converted to Hunting Rule:**
- [x] No
- [ ] Yes — Platform: ___ | Rule Name: ___

**Log/Visibility Gap Found:**
- [ ] No
- [x] Yes — Gap: No visibility into PyPI package content or setup.py code at install time; detection relies entirely on behavioral telemetry post-execution

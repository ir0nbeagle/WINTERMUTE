# Supply Chain: Compromised Base Docker Image in CI/CD Pipeline

**Hunt ID:** H-0032
**Date Created:** 2026-04-22
**Status:** Active
**Analyst:** ir0n
**Source:** https://unit42.paloaltonetworks.com/docker-hub-malicious-images/
**Platform:** CrowdStrike Falcon / Google SecOps SIEM
**ATT&CK Techniques:** T1195.002 — Compromise Software Supply Chain, T1610 — Deploy Container, T1552.007 — Container API, T1059.004 — Unix Shell
**ATT&CK Tactics:** Initial Access, Execution, Credential Access
**Priority:** High

---

## LEARN — Threat Context

### Threat Summary
Threat actors are publishing trojanized base Docker images to Docker Hub with names similar to official images (python-slim, ubuntu-lts, node-alpine). These images contain a backdoor that activates when the container starts, stealing cloud credentials from the container environment and reaching back to a C2. CI/CD pipelines that pull base images without digest pinning are at risk.

### MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic | Usage |
|-------------|----------------|--------|-------|
| T1195.002 | Compromise Software Supply Chain | Initial Access | Trojanized Docker Hub images pulled by CI/CD |
| T1610 | Deploy Container | Execution | Container spun up with malicious entrypoint |
| T1552.007 | Container API | Credential Access | Steal AWS/GCP/Azure credentials from container metadata |
| T1059.004 | Unix Shell | Execution | Bash script in entrypoint runs C2 callback |

---

## OBSERVE — Hypothesis Development

### Hunt Hypothesis
> "Trojanized Docker base images pulled by CI/CD runners are executing shell commands on container startup that reach back to attacker infrastructure, observable as container processes making outbound connections to non-whitelisted IP ranges immediately after container start in CrowdStrike Falcon for Containers telemetry."

---

## CHECK — Query Execution Plan

### Query Notes
- **Recommended time range:** 30 days
- **Focus:** Container workload telemetry — requires Falcon for Containers

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
- [ ] Other: Unknown — Docker Hub supply chain actors

**Converted to Detection Rule:**
- [x] No
- [ ] Yes — Platform: ___ | Rule Name: ___

**Converted to Hunting Rule:**
- [x] No
- [ ] Yes — Platform: ___ | Rule Name: ___

**Log/Visibility Gap Found:**
- [ ] No
- [x] Yes — Gap: Falcon for Containers not deployed on all CI/CD runner pools; partial container telemetry coverage only

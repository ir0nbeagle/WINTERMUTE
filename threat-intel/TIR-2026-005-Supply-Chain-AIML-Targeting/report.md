---
id: TIR-2026-005
title: "Supply Chain Targeting of the AI/ML Developer Ecosystem"
date: 2026-04-20
analyst: ir0n
tlp: AMBER
priority: High
status: hunt-created

linked_hunts: [H-0029, H-0032, H-0035]

threat_actors:
  - name: TeamPCP
    type: cybercriminal
    motivation: financial
    sectors: [technology, ai-ml, software-development]
    geo: global
  - name: Unknown Supply Chain Actor
    type: cybercriminal
    motivation: financial
    sectors: [technology, software-development]
    geo: global

techniques:
  - T1195.001
  - T1195.002
  - T1059.006
  - T1056.001
  - T1041
  - T1552
  - T1027
  - T1610

tools:
  - name: Malicious PyPI Package
    category: execution
    description: Post-install hook in setup.py executes credential harvesting payload
  - name: Typosquatted npm Package
    category: execution
    description: Postinstall hook installs persistent Node.js keylogger
  - name: Trojanized Docker Image
    category: execution
    description: Backdoored base image with shell callback on container start
  - name: requests (abused)
    category: exfiltration
    description: Python requests library used by malicious packages for C2 exfil

iocs:
  - type: package
    value: torch-utils-ext
    context: TeamPCP malicious PyPI package — mimics torch utility library; harvests AI provider API keys
    expires: 2026-07-20
    tlp: WHITE
  - type: package
    value: sklearn-accelerate
    context: TeamPCP malicious PyPI package — mimics scikit-learn; exfils AWS credentials
    expires: 2026-07-20
    tlp: WHITE
  - type: package
    value: huggingface-hub-fast
    context: TeamPCP malicious PyPI package — mimics HuggingFace library
    expires: 2026-07-20
    tlp: WHITE
  - type: package
    value: reakt
    context: Typosquatted npm package mimicking React; installs keylogger via postinstall
    expires: 2026-07-20
    tlp: WHITE
  - type: package
    value: expresss
    context: Typosquatted npm package mimicking Express.js framework
    expires: 2026-07-20
    tlp: WHITE
  - type: ip
    value: 104.21.77.42
    context: TeamPCP C2 endpoint — receives API key exfil via HTTPS POST
    expires: 2026-07-20
    tlp: AMBER
  - type: ip
    value: 172.67.183.95
    context: Secondary TeamPCP infrastructure — Cloudflare-proxied; hosts exfil receiver
    expires: 2026-07-20
    tlp: AMBER
  - type: sha256
    value: 2c624232cdd221771294dfbb310acbc8c77f4b0d739d7f5c22f6b2e3e57d412a
    context: TeamPCP setup.py payload — MD5 of malicious post-install hook
    expires: 2026-10-20
    tlp: AMBER
---

## Executive Summary

Multiple unrelated threat actors are converging on the AI/ML developer supply chain as a high-value target. TeamPCP (PyPI), an unnamed actor (typosquatted npm), and Docker Hub supply chain attackers are all deploying malicious packages that execute credential harvesting payloads at install time. The AI/ML ecosystem is particularly attractive because developers routinely have API keys for OpenAI, Anthropic, AWS SageMaker, and HuggingFace in their environments — keys that can be monetized via LLM credit resale. This consolidated report drove three hunt workstreams targeting our developer endpoints.

---

## Threat Actor Profile

| Field | Details |
|-------|---------|
| Name | TeamPCP (PyPI); Unknown (npm/Docker) |
| Type | Cybercriminal |
| Motivation | Financial — API key theft, LLM credit abuse, credential resale |
| Active Since | September 2025 (TeamPCP); April 2026 (npm campaign) |
| Target Sectors | AI/ML research, software development, data science |
| Geographic Focus | Global — targeting developer endpoints worldwide |

---

## Technical Analysis

### Kill Chain

1. **Initial Access** — Developer installs typosquatted/trojanized package during normal workflow
2. **Execution** — Post-install hook (setup.py, package.json scripts, Docker ENTRYPOINT) runs immediately
3. **Credential Access** — Scans environment variables, ~/.config, ~/.aws, ~/.openai for API keys
4. **Exfiltration** — Keys sent via HTTPS POST to attacker-controlled endpoint
5. **Persistence** — npm keylogger variety maintains persistent Node.js process for ongoing key capture

### MITRE ATT&CK Mapping

| Technique | Name | Notes |
|-----------|------|-------|
| T1195.001 | Supply Chain: Software Dependencies | PyPI and npm package repositories |
| T1195.002 | Supply Chain: Software Supply Chain | Trojanized Docker Hub base images |
| T1059.006 | Python | setup.py post-install hook execution |
| T1056.001 | Keylogging | npm package hooks Node.js stdin |
| T1041 | Exfiltration Over C2 Channel | API keys via HTTPS POST |
| T1552 | Unsecured Credentials | Scans env vars and AI provider config files |
| T1027 | Obfuscated Files | Base64-encoded payloads in package.json scripts |
| T1610 | Deploy Container | Trojanized Docker images with malicious ENTRYPOINT |

### Tools Used

- **Malicious setup.py hooks** — Python post-install execution; no user interaction required
- **npm postinstall scripts** — Runs automatically on `npm install`; can install persistent processes
- **Trojanized ENTRYPOINT scripts** — Shell callback on every container start

---

## Recommended Hunt Actions

- **Primary hunt (H-0029):** pip spawning Python child with immediate outbound connection to non-PyPI endpoint
- **Secondary hunt (H-0035):** Long-running Node.js process with periodic connections to non-CDN IPs
- **Container hunt (H-0032):** Container process connecting to non-whitelisted external IPs on startup

**Suggested platforms:** CrowdStrike Falcon + Falcon for Containers, Google SecOps

---

## References

- Phylum TeamPCP Analysis: https://blog.phylum.io/teamPCP-targets-ai-ml-pypi
- Socket.dev npm Keylogger Report: https://socket.dev/blog/npm-typosquat-keylogger-2026
- Unit42 Docker Hub Malicious Images: https://unit42.paloaltonetworks.com/docker-hub-malicious-images/

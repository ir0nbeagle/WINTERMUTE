---
id: TIR-2026-009
title: "Volt Typhoon: Living-off-the-Land Pre-Positioning in Critical Infrastructure"
date: 2026-06-10
analyst: ir0n
tlp: AMBER
priority: Critical
status: new

linked_hunts: []

threat_actors:
  - name: Volt Typhoon
    type: nation-state
    motivation: espionage
    sectors: [energy, water, telecommunications, transportation, defense-industrial-base]
    geo: us

techniques:
  - T1190
  - T1078
  - T1133
  - T1003.001
  - T1059.001
  - T1105
  - T1090.002
  - T1018
  - T1049
  - T1087.002

tools:
  - name: Impacket
    category: lateral-movement
    description: Open-source Python toolkit for SMB/WMI lateral movement; used with harvested credentials
  - name: FRP (Fast Reverse Proxy)
    category: c2
    description: Open-source reverse proxy tool used for tunneling C2 through legitimate services
  - name: Earthworm
    category: c2
    description: SOCKS tunnel tool used for network pivoting through OT/IT boundary
  - name: LOLBins (various)
    category: execution
    description: certutil, wmic, netsh, ntdsutil — living-off-the-land to minimize footprint

iocs:
  - type: ip
    value: 174.138.56.195
    context: Volt Typhoon SOHO router hop — compromised Cisco RV VPN device used as proxy
    expires: 2026-09-10
    tlp: AMBER
  - type: ip
    value: 167.248.133.56
    context: KV-botnet node — compromised SOHO device relaying Volt Typhoon traffic
    expires: 2026-09-10
    tlp: AMBER
  - type: domain
    value: vpn-secure-connect[.]org
    context: Volt Typhoon proxy infrastructure domain
    expires: 2026-09-10
    tlp: AMBER
  - type: sha256
    value: b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2
    context: FRP reverse proxy binary — custom compiled for Volt Typhoon operations
    expires: 2026-09-10
    tlp: AMBER
---

## Executive Summary

Volt Typhoon (Bronze Silhouette) is a Chinese state-sponsored threat actor pre-positioning in US critical infrastructure with a focus on operational disruption capability rather than immediate espionage. Unlike typical CN actors, Volt Typhoon avoids custom malware, relying almost exclusively on built-in Windows tools (LOLBins) and legitimate network tools to blend into normal traffic. CISA's Emergency Directive 24-02 and Five Eyes advisory confirm active, ongoing presence in energy, water, and telecommunications sectors. This report is in the new queue — hunt development needed to detect LOLBin-heavy intrusion patterns with minimal malware footprint.

---

## Threat Actor Profile

| Field | Details |
|-------|---------|
| Name | Volt Typhoon / Bronze Silhouette / Vanguard Panda |
| Type | Nation-state (PRC) |
| Motivation | Espionage + pre-positioning for potential OT disruption |
| Active Since | Mid-2021 (confirmed; likely earlier) |
| Target Sectors | Energy, water, telecommunications, transportation, DIB |
| Geographic Focus | United States (Guam OT network focus; continental US infrastructure) |

---

## Technical Analysis

### Kill Chain

1. **Initial Access** — Exploits internet-facing VPN/firewall appliances (Fortinet, Cisco ASA, Citrix); uses SOHO router botnet (KV-botnet) to proxy activity
2. **Persistence** — Minimal footprint; abuses legitimate accounts; may use scheduled tasks via schtasks
3. **Credential Access** — Dumps LSASS via comsvcs.dll minidump; SAM hive extraction
4. **Discovery** — wmic, netsh, ipconfig, route, net commands for environment mapping; avoids Nmap/scanners
5. **Lateral Movement** — Impacket SMBExec/WMIExec with harvested credentials; stays on-network
6. **C2** — FRP or Earthworm SOCKS tunnels; traffic proxied through compromised SOHO devices
7. **Objective** — Long-term persistence; capability to disrupt OT systems if directed

### MITRE ATT&CK Mapping

| Technique | Name | Notes |
|-----------|------|-------|
| T1190 | Exploit Public-Facing Application | Fortinet/Cisco/Citrix initial access |
| T1078 | Valid Accounts | Credential-based access using harvested accounts |
| T1133 | External Remote Services | VPN access via compromised credentials |
| T1003.001 | LSASS Memory | comsvcs.dll MiniDump for credential access |
| T1059.001 | PowerShell | Used sparingly; prefers built-in CMD tools |
| T1105 | Ingress Tool Transfer | FRP/Earthworm downloaded via certutil |
| T1090.002 | External Proxy | KV-botnet SOHO router proxy for traffic obfuscation |
| T1018 | Remote System Discovery | wmic, net view, ping sweeps via LOLBins |
| T1049 | System Network Connections | netstat, netsh for network mapping |
| T1087.002 | Domain Account Discovery | net user /domain, net group for AD enumeration |

---

## Recommended Hunt Actions

> **STATUS: New — awaiting hunt prioritization and query development.**

- **Proposed hunt #1:** LOLBin chain — certutil downloading to temp directory followed by immediate execution
- **Proposed hunt #2:** comsvcs.dll MiniDump invocation (LSASS dump without Mimikatz binary)
- **Proposed hunt #3:** Outbound SOCKS proxy patterns — FRP tunnel indicators (high-frequency low-data connections to single external IP)
- **Proposed hunt #4:** wmic + net commands in sequence from single host within short time window (discovery phase)

**Suggested platforms:** CrowdStrike (process chain + network), Google SecOps YARA-L (LOLBin sequence detection)

---

## References

- CISA Emergency Directive 24-02: https://www.cisa.gov/news-events/directives/ed-24-02
- Five Eyes Volt Typhoon Advisory: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a
- Microsoft Volt Typhoon Blog: https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure/
- Secureworks Bronze Silhouette: https://www.secureworks.com/blog/volt-typhoon-analysis

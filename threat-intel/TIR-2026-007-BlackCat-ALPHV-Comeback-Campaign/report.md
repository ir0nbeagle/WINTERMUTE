---
id: TIR-2026-007
title: "BlackCat/ALPHV Comeback: Infrastructure Reboot Post-Law-Enforcement Disruption"
date: 2026-05-28
analyst: ir0n
tlp: AMBER
priority: Critical
status: new

linked_hunts: []

threat_actors:
  - name: BlackCat/ALPHV
    type: cybercriminal
    motivation: financial
    sectors: [healthcare, legal, financial-services, critical-infrastructure]
    geo: global

techniques:
  - T1003.001
  - T1003.002
  - T1078.002
  - T1484.001
  - T1021.002
  - T1082
  - T1135
  - T1083
  - T1486
  - T1491.002

tools:
  - name: Mimikatz
    category: credential-access
    description: Primary credential dumping tool — sekurlsa::logonpasswords and lsadump::dcsync
  - name: Cobalt Strike
    category: c2
    description: Primary post-exploitation framework; beacons via HTTPS to team servers
  - name: AdFind
    category: discovery
    description: Active Directory enumeration — targets, OUs, group memberships
  - name: Netscan
    category: discovery
    description: Internal network scanning for lateral movement targeting
  - name: RClone
    category: exfiltration
    description: Used to sync exfiltrated data to MEGA cloud before encryption
  - name: AlphV Encryptor (Rust)
    category: execution
    description: Cross-platform Rust encryptor; supports Windows, Linux, VMware ESXi; intermittent encryption mode

iocs:
  - type: ip
    value: 84.247.133.198
    context: BlackCat/ALPHV Cobalt Strike team server — reactivated post-LE disruption
    expires: 2026-08-28
    tlp: AMBER
  - type: ip
    value: 193.42.33.144
    context: ALPHV affiliate exfiltration staging via RClone
    expires: 2026-08-28
    tlp: AMBER
  - type: domain
    value: alphvmmm27o3rrkfbolpoya6klduoiulbqs4clyso2obdmxu2notjfvqd.onion
    context: Current ALPHV leak site (post-relaunch) — monitor for victim listings
    expires:
    tlp: WHITE
  - type: sha256
    value: f8f0b3836b1cde9547b7c9e3f27fe1d5a0e9b8c7d6e5f4a3b2c1d0e9f8a7b6c5
    context: BlackCat Rust encryptor — latest variant with ESXi targeting capability
    expires: 2026-10-28
    tlp: AMBER
  - type: sha256
    value: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678
    context: RClone binary — modified version with hardcoded MEGA credentials
    expires: 2026-10-28
    tlp: AMBER
  - type: url
    value: https://alphvmm2xzrqazqfxsq7s3bqefmphfxmydixfmyakyf.onion/upload
    context: ALPHV data extortion portal — used for victim negotiation and proof-of-data
    expires:
    tlp: WHITE
---

## Executive Summary

BlackCat/ALPHV has relaunched operations following the February 2024 FBI disruption and subsequent exit scam. Intelligence from multiple IR firms indicates affiliates have reconstituted infrastructure and resumed targeting, with particular focus on healthcare following the Change Healthcare incident demonstrating the sector's propensity to pay. New TTPs include DCSsync via Mimikatz for mass credential harvest, RClone for high-speed data exfiltration to MEGA prior to encryption, and an updated Rust-based encryptor with improved ESXi targeting. **No hunt has been created for this report yet — pending prioritization and query development.**

---

## Threat Actor Profile

| Field | Details |
|-------|---------|
| Name | BlackCat / ALPHV / Noberus |
| Type | Ransomware-as-a-Service |
| Motivation | Financial — ransom payments + double extortion |
| Active Since | November 2021 (relaunched 2024 post-disruption) |
| Target Sectors | Healthcare, legal, financial services, critical infrastructure |
| Geographic Focus | Global (US primary target) |

---

## Technical Analysis

### Kill Chain

1. **Initial Access** — Exploits unpatched VPN/firewall vulnerabilities or purchases access from brokers; phishing less common
2. **Persistence** — Cobalt Strike beacon; may deploy additional RMM tools as backup
3. **Credential Access** — Mimikatz sekurlsa::logonpasswords + DCSync to obtain domain admin
4. **Discovery** — ADFind for AD topology; Netscan for internal host enumeration
5. **Lateral Movement** — SMB with harvested domain admin credentials; may use WMI for execution
6. **Exfiltration** — RClone syncs data directories to MEGA prior to encryption (double extortion)
7. **Impact** — Rust encryptor; cross-platform (Windows + Linux + ESXi); supports intermittent and full modes

### MITRE ATT&CK Mapping

| Technique | Name | Notes |
|-----------|------|-------|
| T1003.001 | LSASS Memory | Mimikatz sekurlsa::logonpasswords |
| T1003.002 | Security Account Manager | SAM hive extraction |
| T1078.002 | Domain Accounts | DCSync to obtain all domain credentials |
| T1484.001 | Group Policy Modification | GPO-based malware deployment observed in some cases |
| T1021.002 | SMB/Windows Admin Shares | Lateral movement with domain admin creds |
| T1082 | System Information Discovery | WMI/PowerShell enumeration |
| T1135 | Network Share Discovery | Targeting file shares for encryption scope |
| T1083 | File and Directory Discovery | Pre-encryption directory traversal |
| T1486 | Data Encrypted for Impact | Rust encryptor — intermittent + ESXi modes |
| T1491.002 | External Defacement | Ransom note on desktop + printer output |

### Tools Used

- **Mimikatz** — Primary credential dumper; DCSync extension for mass domain credential harvest
- **Cobalt Strike** — C2 beacons with malleable profiles to evade detection
- **ADFind** — AD reconnaissance; targets high-value OUs and group memberships
- **RClone** — Modified binary with MEGA API credentials hardcoded for rapid exfil
- **ALPHV Rust Encryptor** — Cross-platform; targets VMware ESXi in addition to Windows/Linux

---

## Recommended Hunt Actions

> **STATUS: Hunt not yet created — this report is in the new queue for prioritization.**

- **Proposed hunt #1:** Non-system process reading LSASS memory (Mimikatz detection)
- **Proposed hunt #2:** DCSync operation from non-DC host (replication rights abuse)
- **Proposed hunt #3:** RClone connecting to MEGA endpoints with large outbound data volume
- **Behavioral detection:** Cobalt Strike beacon pattern (beacon sleep jitter + HTTPS to non-categorized domains)

**Suggested platforms:** CrowdStrike (LSASS + network), Google SecOps YARA-L (DCSync), Microsoft Defender for Identity (DCSync)

---

## References

- FBI ALPHV Indicators: https://www.ic3.gov/Media/News/2023/231219.pdf
- Mandiant ALPHV Analysis: https://www.mandiant.com/resources/blog/alphv-ransomware-backup
- Sophos BlackCat/ALPHV 2024 Update: https://news.sophos.com/en-us/2024/03/blackcat-alphv-exit-scam/
- Change Healthcare Incident Report: https://www.hhs.gov/about/news/2024/03/13/hhs-statement-change-healthcare.html

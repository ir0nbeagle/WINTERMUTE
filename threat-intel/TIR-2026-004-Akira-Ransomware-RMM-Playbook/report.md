---
id: TIR-2026-004
title: "Akira Ransomware: RMM Tool Abuse and Pre-Encryption Playbook"
date: 2026-05-16
analyst: ir0n
tlp: AMBER
priority: Critical
status: hunt-created

linked_hunts: [H-0038]

threat_actors:
  - name: Akira Ransomware
    type: cybercriminal
    motivation: financial
    sectors: [manufacturing, healthcare, education, smb]
    geo: global

techniques:
  - T1219
  - T1486
  - T1490
  - T1112
  - T1562.001
  - T1059.001
  - T1021.001

tools:
  - name: AnyDesk
    category: c2
    description: Legitimate RMM tool abused for persistent remote access and lateral movement
  - name: Splashtop
    category: c2
    description: Alternative RMM tool installed as redundant C2 channel
  - name: Atera
    category: c2
    description: MSP RMM platform abused to deploy scripts and move laterally
  - name: Akira Encryptor (Linux/Windows)
    category: execution
    description: ChaCha20 + RSA-4096 encryption; targets NAS and VMware ESXi in addition to Windows
  - name: PowerShell Empire
    category: execution
    description: Post-exploitation framework observed in some Akira intrusions

iocs:
  - type: ip
    value: 194.165.16.11
    context: Akira affiliate C2 — observed in multiple IR engagements via AnyDesk relay
    expires: 2026-08-16
    tlp: AMBER
  - type: ip
    value: 45.61.136.130
    context: Akira exfiltration staging server
    expires: 2026-08-16
    tlp: AMBER
  - type: sha256
    value: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
    context: Akira Windows encryptor — variant targeting manufacturing sector
    expires: 2026-10-16
    tlp: AMBER
  - type: sha256
    value: 9f8e7d6c5b4a3928170615043c2b1a0f9e8d7c6b5a4938271605040302010f9e
    context: Akira Linux/ESXi encryptor variant
    expires: 2026-10-16
    tlp: AMBER
  - type: filename
    value: winupd_svc.msi
    context: AnyDesk silent MSI installer renamed to masquerade as Windows update
    expires: 2026-08-16
    tlp: AMBER
  - type: domain
    value: akiraefceqruaza.onion
    context: Akira leak site — monitor for victim organization listings
    expires:
    tlp: WHITE
---

## Executive Summary

Akira ransomware affiliates have adopted a distinctive pre-encryption playbook centered on legitimate RMM tool abuse. Affiliates gain initial access via stolen VPN credentials or unpatched Cisco ASA vulnerabilities, then install AnyDesk, Splashtop, or Atera via silent MSI to establish persistent remote access outside normal EDR detection. This report triggered hunt H-0038 which confirmed active Akira pre-ransomware activity on a finance server, resulting in host isolation and IR engagement before encryption occurred.

---

## Threat Actor Profile

| Field | Details |
|-------|---------|
| Name | Akira Ransomware (affiliate model) |
| Type | Ransomware-as-a-Service |
| Motivation | Financial — ransom + double extortion |
| Active Since | March 2023 |
| Target Sectors | Manufacturing, healthcare, education, SMB |
| Geographic Focus | North America, Europe |

---

## Technical Analysis

### Kill Chain

1. **Initial Access** — Cisco ASA/FTD exploitation (CVE-2023-20269) or stolen VPN credentials from broker markets
2. **Persistence** — Silent RMM tool install (AnyDesk/Splashtop MSI) outside business hours
3. **Discovery** — Network scanning via netscan.exe; Active Directory enumeration via ADFind
4. **Lateral Movement** — RDP using harvested credentials; RMM relay for hands-on-keyboard access
5. **Defense Evasion** — Windows Defender disabled via registry; AV processes killed
6. **Impact** — VSS deletion, ChaCha20 encryption; ESXi/NAS variants deployed separately

### MITRE ATT&CK Mapping

| Technique | Name | Notes |
|-----------|------|-------|
| T1219 | Remote Access Software | AnyDesk/Splashtop/Atera for persistent C2 |
| T1486 | Data Encrypted for Impact | ChaCha20 + RSA-4096; targets .vmdk, .vhd, databases |
| T1490 | Inhibit System Recovery | VSS deletion; disables Windows backup service |
| T1112 | Modify Registry | DisableAntiSpyware + DisableRealtimeMonitoring registry keys |
| T1562.001 | Disable or Modify Tools | Kills ~30 security tool processes via taskkill loop |
| T1059.001 | PowerShell | PowerShell Empire for post-exploitation in some cases |
| T1021.001 | Remote Desktop Protocol | Lateral movement after credential harvesting |

### Tools Used

- **AnyDesk** — Primary persistent access; free tier allows unauthenticated relay
- **Splashtop/Atera** — Redundant channels; MSP tools harder to alert on than custom RATs
- **netscan.exe** (SoftPerfect) — Network discovery during reconnaissance phase
- **ADFind** — Active Directory enumeration to map high-value targets
- **Akira Encryptor** — Separate Windows and Linux binaries; ESXi variant runs on hypervisor directly

---

## Recommended Hunt Actions

- **Primary hunt (H-0038):** RMM tool installation via msiexec from non-admin accounts, especially outside business hours
- **Secondary hunt:** Windows Defender registry modification (DisableAntiSpyware key)
- **Behavioral detection:** Network connections to AnyDesk/Splashtop relay infrastructure from servers (not workstations)

**Suggested platforms:** CrowdStrike (primary), Google SecOps YARA-L for combined RMM + registry rule

---

## References

- CISA Advisory AA24-109A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a
- SentinelOne Akira Deep-Dive: https://www.sentinelone.com/blog/akira-ransomware-targeting-cisco-anydesk/
- Sophos Akira Technical Analysis: https://news.sophos.com/en-us/2023/06/09/akira-ransomware/

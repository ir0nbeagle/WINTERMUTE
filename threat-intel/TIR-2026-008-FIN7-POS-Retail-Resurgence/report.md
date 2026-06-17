---
id: TIR-2026-008
title: "FIN7 Retail and POS Resurgence: USB BadUSB Campaign Targeting Physical Stores"
date: 2026-06-02
analyst: ir0n
tlp: AMBER
priority: High
status: in-review

linked_hunts: []

threat_actors:
  - name: FIN7
    type: cybercriminal
    motivation: financial
    sectors: [retail, hospitality, restaurant, financial-services]
    geo: us-europe

techniques:
  - T1091
  - T1059.001
  - T1059.005
  - T1055
  - T1105
  - T1071.001
  - T1041

tools:
  - name: POWERPLANT
    category: c2
    description: FIN7 PowerShell-based backdoor; uses DNS TXT records for C2 comms
  - name: DICELOADER
    category: c2
    description: FIN7 custom loader; downloads additional payloads from C2
  - name: Carbanak Framework
    category: execution
    description: FIN7 custom post-exploitation framework for POS system targeting
  - name: TinyMet
    category: c2
    description: Tiny Meterpreter stager used in USB drop campaigns
  - name: BIRDWATCH
    category: credential-access
    description: FIN7 memory scraper targeting POS RAM for card track data

iocs:
  - type: domain
    value: updates-cdn-service[.]com
    context: FIN7 POWERPLANT C2 domain — DNS TXT records used for command delivery
    expires: 2026-09-02
    tlp: AMBER
  - type: domain
    value: software-patch-delivery[.]net
    context: FIN7 DICELOADER staging domain
    expires: 2026-09-02
    tlp: AMBER
  - type: ip
    value: 91.92.254.25
    context: FIN7 infrastructure — DICELOADER C2 server
    expires: 2026-09-02
    tlp: AMBER
  - type: sha256
    value: d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5
    context: POWERPLANT PowerShell backdoor — delivered via USB autorun
    expires: 2026-09-02
    tlp: AMBER
  - type: filename
    value: FlashDriveSetup.exe
    context: FIN7 USB dropper filename — BadUSB campaign targeting retail POS
    expires: 2026-09-02
    tlp: AMBER
  - type: filename
    value: POWERPLANT.ps1
    context: FIN7 PowerShell C2 beacon script — obfuscated with base64 + XOR
    expires: 2026-09-02
    tlp: AMBER
---

## Executive Summary

FIN7 (Carbanak Group) has resumed targeted campaigns against US and European retail and restaurant chains using a BadUSB physical delivery method. Packages mailed to store managers contain a USB drive labeled as a "loyalty program update" or "gift card activation tool." When inserted, the device automates keystrokes to download and execute POWERPLANT or DICELOADER. Final-stage tooling targets POS RAM memory with BIRDWATCH to scrape payment card track data. This report is in review pending assessment of our retail partners' exposure and determination of hunt scope.

---

## Threat Actor Profile

| Field | Details |
|-------|---------|
| Name | FIN7 / Carbanak Group / Navigator Group |
| Type | Cybercriminal (sophisticated, organized) |
| Motivation | Financial — payment card theft, ransomware (more recently) |
| Active Since | 2013 |
| Target Sectors | Retail, hospitality, restaurant, financial services |
| Geographic Focus | United States, Europe |

---

## Technical Analysis

### Kill Chain

1. **Initial Access** — Mailed USB drive to store manager; device acts as HID keyboard (BadUSB)
2. **Execution** — Device types PowerShell one-liner to download and execute stager
3. **C2 Establishment** — POWERPLANT beacon via DNS TXT or DICELOADER HTTPS callback
4. **Lateral Movement** — Moves to POS terminals via RDP or SMB from infected back-office system
5. **Collection** — BIRDWATCH scrapes POS process memory for card track data (Track 1/2)
6. **Exfiltration** — Card data exfiltrated via encrypted channel to FIN7 infrastructure

### MITRE ATT&CK Mapping

| Technique | Name | Notes |
|-----------|------|-------|
| T1091 | Replication Through Removable Media | BadUSB HID attack via mailed USB device |
| T1059.001 | PowerShell | POWERPLANT beacon; initial download stager |
| T1059.005 | Visual Basic | Some variants use VBScript dropper |
| T1055 | Process Injection | BIRDWATCH injected into POS process for memory scraping |
| T1105 | Ingress Tool Transfer | DICELOADER downloads additional payloads |
| T1071.001 | Application Layer Protocol: Web | HTTPS C2 with domain fronting |
| T1041 | Exfiltration Over C2 Channel | Card data exfil via C2 channel |

---

## Recommended Hunt Actions

> **STATUS: In review — hunt scope pending partner environment assessment.**

- **Proposed hunt #1:** PowerShell execution spawned from HID device (parent process: kbd handler / explorer)
- **Proposed hunt #2:** POS process (typically javaw.exe or proprietary POS exe) with child process or memory read by non-system process
- **Proposed hunt #3:** DNS TXT record queries from endpoints — unusual for corporate use

**Suggested platforms:** CrowdStrike, Google SecOps

---

## References

- Mandiant FIN7 Evolution 2024: https://www.mandiant.com/resources/blog/fin7-evolution-targeting
- FBI FIN7 Indictment: https://www.justice.gov/opa/pr/three-members-notorious-international-cybercrime-group-fin7
- CISA FIN7 Advisory: https://www.cisa.gov/news-events/alerts/2022/04/11/fin7-targeting-us-businesses

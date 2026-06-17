---
id: TIR-2026-002
title: "LockBit 3.0 Accelerated Healthcare Sector Targeting"
date: 2026-04-05
analyst: ir0n
tlp: AMBER
priority: Critical
status: hunt-created

linked_hunts: [H-0030]

threat_actors:
  - name: LockBit 3.0
    type: cybercriminal
    motivation: financial
    sectors: [healthcare, manufacturing, legal]
    geo: global

techniques:
  - T1021.002
  - T1570
  - T1486
  - T1490
  - T1562.001
  - T1078

tools:
  - name: PsExec
    category: lateral-movement
    description: Used to remotely execute LockBit payload via admin shares
  - name: LockBit 3.0 Encryptor
    category: execution
    description: AES-256 + RSA-2048 ransomware encryptor; supports intermittent encryption mode
  - name: StealBit
    category: exfiltration
    description: Custom exfiltration tool used before encryption for double-extortion
  - name: NirSoft Network Password Recovery
    category: credential-access
    description: Recovers saved Windows credentials from credential store

iocs:
  - type: ip
    value: 5.188.87.194
    context: LockBit affiliate C2 infrastructure — observed in SMB fan-out campaigns
    expires: 2026-07-05
    tlp: AMBER
  - type: ip
    value: 185.220.101.47
    context: Tor exit node used by affiliates for initial access
    expires: 2026-07-05
    tlp: AMBER
  - type: sha256
    value: 0e04e4f9523c8b44f3f517b82c1c50f3f70aeebfe5a57b1a4d2a6b3a0f5d6c8a
    context: LockBit 3.0 encryptor binary — healthcare variant with intermittent encryption
    expires: 2026-10-01
    tlp: AMBER
  - type: filename
    value: svchost_updater.exe
    context: LockBit dropper masquerading as Windows service update
    expires: 2026-07-05
    tlp: AMBER
  - type: domain
    value: lockbit3ouyhwujm.onion
    context: LockBit 3.0 leak site — for tracking victim data publication
    expires:
    tlp: WHITE
  - type: sha256
    value: 3f2504e04f8956d14c8a8c5a6c3b9d1e7f4a2b8c9d0e1f2a3b4c5d6e7f8091a2
    context: StealBit exfiltration tool binary
    expires: 2026-10-01
    tlp: AMBER
---

## Executive Summary

LockBit 3.0 affiliates have accelerated targeting of healthcare organizations following the disruption of other major RaaS programs. CISA advisory AA23-075A confirms active exploitation of unpatched VPN appliances as the primary initial access vector. Post-access activity follows a consistent playbook: credential harvesting, SMB lateral movement via PsExec, StealBit data exfiltration for double-extortion leverage, VSS deletion, and AES-256 file encryption. Given our organization's healthcare data handling, this report was created to drive proactive hunt coverage.

---

## Threat Actor Profile

| Field | Details |
|-------|---------|
| Name | LockBit 3.0 (affiliate model) |
| Type | Ransomware-as-a-Service |
| Motivation | Financial — ransom payments + data extortion |
| Active Since | 2019 (LockBit 3.0 since June 2022) |
| Target Sectors | Healthcare, manufacturing, legal, financial services |
| Geographic Focus | North America, Europe, Australia |

---

## Technical Analysis

### Kill Chain

1. **Initial Access** — Exploits unpatched Citrix/Fortinet VPN vulnerabilities (CVE-2023-4966, CVE-2023-27997) or phishing; credentials purchased from initial access brokers
2. **Persistence** — Creates local admin accounts; may deploy AnyDesk or Splashtop as backup access
3. **Credential Access** — NirSoft tools + LSASS dumping to harvest domain credentials
4. **Lateral Movement** — PsExec + SMB admin shares (C$, ADMIN$) to distribute payload
5. **Exfiltration** — StealBit copies sensitive data to affiliate-controlled server (double extortion)
6. **Impact** — VSS deletion, AV/EDR termination, AES-256 + RSA-2048 encryption

### MITRE ATT&CK Mapping

| Technique | Name | Notes |
|-----------|------|-------|
| T1021.002 | SMB/Windows Admin Shares | Primary lateral movement vector |
| T1570 | Lateral Tool Transfer | PsExec pushes payload to targets |
| T1486 | Data Encrypted for Impact | Intermittent encryption to evade detection |
| T1490 | Inhibit System Recovery | vssadmin + wbadmin delete backup catalog |
| T1562.001 | Disable or Modify Tools | Kills ~40 AV/EDR processes before encryption |
| T1078 | Valid Accounts | Harvested domain credentials for all lateral movement |

### Tools Used

- **PsExec** — Remote execution; drops payload to C$ then runs via sc.exe
- **StealBit** — Custom exfil tool; compressed and staged before encryption begins
- **NirSoft Network Password Recovery** — Credential harvesting from Windows credential manager
- **LockBit 3.0 Encryptor** — Supports intermittent mode (encrypts first 4KB of each file, faster)

---

## Recommended Hunt Actions

- **Primary hunt (H-0030):** SMB fan-out from single host to >10 internal targets within 1 hour
- **Secondary hunt:** vssadmin and wbadmin deletion commands outside patch windows
- **Behavioral detection:** PsExec installation on hosts not in IT admin asset group

**Suggested platforms:** CrowdStrike (primary), Google SecOps YARA-L for SMB fan-out rule

---

## References

- CISA Advisory AA23-075A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a
- FBI LockBit Indicators: https://www.ic3.gov/Media/News/2022/220204.pdf
- Trend Micro LockBit 3.0 Analysis: https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-lockbit

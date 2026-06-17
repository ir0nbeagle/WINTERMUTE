---
id: TIR-2026-003
title: "Insider Threat: Pre-Departure Data Exfiltration Behavioral Patterns"
date: 2026-04-12
analyst: ir0n
tlp: AMBER
priority: High
status: hunt-created

linked_hunts: [H-0031, H-0034, H-0037]

threat_actors:
  - name: Malicious Insider — Departing Employee
    type: insider
    motivation: financial
    sectors: [technology, financial-services, defense]
    geo: internal

techniques:
  - T1074.001
  - T1560.001
  - T1567.002
  - T1048.003
  - T1528
  - T1078
  - T1530

tools:
  - name: 7-Zip
    category: exfiltration
    description: Used to compress and archive large directories before exfil
  - name: Dropbox Client
    category: exfiltration
    description: Personal cloud sync client used for bulk uploads
  - name: Mega.nz Browser Upload
    category: exfiltration
    description: Web-based upload to personal Mega.nz storage
  - name: WinSCP
    category: exfiltration
    description: Observed in some cases for SFTP exfil to external servers

iocs:
  - type: domain
    value: mega.nz
    context: Personal cloud storage — blocked per policy; any upload from corp endpoint is suspicious
    expires:
    tlp: WHITE
  - type: domain
    value: content.dropboxapi.com
    context: Dropbox content upload API — monitor for high-volume transfers from non-authorized devices
    expires:
    tlp: WHITE
  - type: domain
    value: api.dropboxapi.com
    context: Dropbox API endpoint — bulk operations may indicate automated staging
    expires:
    tlp: WHITE
  - type: regex
    value: '(?i)(source[_-]?code|credentials|customer[_-]?data|pii|proprietary|confidential)\.zip$'
    context: Filename pattern indicating sensitive archive creation in user directories
    expires:
    tlp: AMBER
---

## Executive Summary

This report consolidates behavioral intelligence on pre-departure data exfiltration by insider threats. Analysis of industry incident reports and internal near-misses indicates a consistent pattern: archive creation (7-Zip, native compress), followed by upload to personal cloud storage (Dropbox, Mega.nz, Google Drive personal) during the final 30 days of employment. The risk window is the notice period. This report drove creation of three hunt workstreams (H-0031, H-0034, H-0037) and one confirmed true positive with IR escalation.

---

## Threat Actor Profile

| Field | Details |
|-------|---------|
| Name | Malicious Insider (Departing Employee archetype) |
| Type | Insider Threat |
| Motivation | Financial (IP theft for competitive advantage or sale) |
| Active Since | Ongoing — not actor-specific |
| Target Sectors | Technology, defense contractors, financial services |
| Geographic Focus | Internal to organization |

---

## Technical Analysis

### Kill Chain

1. **Collection** — Employee identifies high-value data (source code, customer records, research data)
2. **Staging** — Creates large archives using 7-Zip or OS-native compress in user-writable directories (Downloads, Desktop)
3. **Exfiltration** — Uploads archive to personal cloud storage via browser or sync client
4. **Cover** — May delete local archives; timing often during off-hours to avoid notice

### MITRE ATT&CK Mapping

| Technique | Name | Notes |
|-----------|------|-------|
| T1074.001 | Local Data Staging | Archives created in Downloads/Desktop/AppData |
| T1560.001 | Archive via Utility | 7-Zip primary; WinRAR, native ZIP also observed |
| T1567.002 | Exfiltration to Cloud Storage | Dropbox, Mega, Google Drive personal, OneDrive personal |
| T1048.003 | Exfiltration over Unencrypted Protocol | HTTP PUT/multipart upload (DLP can inspect) |
| T1528 | Steal Application Access Token | OAuth tokens created for persistent post-offboarding access |
| T1078 | Valid Accounts | Uses own valid credentials — looks legitimate |
| T1530 | Data from Cloud Storage | Accesses internal S3 buckets or SharePoint before staging |

### Tools Used

- **7-Zip** — Most common; command-line use (`7z a -p<password>`) indicates intentional obfuscation
- **Dropbox Client** — Background sync hides exfil in normal traffic patterns
- **Mega.nz** — End-to-end encrypted; DLP cannot inspect content, only detect upload
- **WinSCP** — SFTP to personal VPS; used in more sophisticated insider cases

---

## Recommended Hunt Actions

- **Primary hunt (H-0031):** Archive utility creating files >200MB in user home directories
- **Secondary hunt (H-0034):** OAuth token generation spike from accounts in offboarding status
- **Behavioral detection (H-0037):** High-volume HTTPS transfers to personal cloud storage domains from corp endpoints

**Suggested platforms:** CrowdStrike (file + network events), Okta (token generation), DLP platform

---

## References

- CISA Insider Threat Guidance: https://www.cisa.gov/insider-threat-mitigation
- CERT Insider Threat Center Common Sense Guide (8th Ed.): https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=484738
- Verizon DBIR 2025 — Insider Threat chapter

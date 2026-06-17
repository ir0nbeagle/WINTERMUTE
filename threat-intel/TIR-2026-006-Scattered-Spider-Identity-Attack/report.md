---
id: TIR-2026-006
title: "Scattered Spider: Identity-Centric Attack Campaign — MFA Fatigue and Vishing"
date: 2026-05-08
analyst: ir0n
tlp: AMBER
priority: Critical
status: hunt-created

linked_hunts: [H-0036]

threat_actors:
  - name: Scattered Spider
    type: cybercriminal
    motivation: financial
    sectors: [hospitality, retail, technology, telecommunications]
    geo: us-uk

techniques:
  - T1621
  - T1566.004
  - T1078
  - T1133
  - T1539
  - T1556.006
  - T1598.004

tools:
  - name: EvilGinx2
    category: credential-access
    description: Adversary-in-the-middle phishing proxy; captures session cookies bypassing MFA
  - name: Okta Admin Console (abused)
    category: credential-access
    description: Actors use helpdesk social engineering to gain Okta admin access and disable MFA
  - name: Telegram
    category: c2
    description: Used for team coordination and victim targeting during active intrusions
  - name: ScreenConnect
    category: c2
    description: RMM tool used for persistent remote access after initial VPN compromise

iocs:
  - type: ip
    value: 185.220.101.34
    context: Tor exit node frequently used by Scattered Spider for initial VPN authentication
    expires: 2026-08-08
    tlp: AMBER
  - type: ip
    value: 185.220.100.252
    context: Tor exit node — Scattered Spider vishing infrastructure
    expires: 2026-08-08
    tlp: AMBER
  - type: ip
    value: 45.142.212.100
    context: EvilGinx2 phishing proxy infrastructure
    expires: 2026-08-08
    tlp: AMBER
  - type: domain
    value: okta-helpdesk-support[.]com
    context: Scattered Spider typosquat domain used in helpdesk impersonation vishing
    expires: 2026-08-08
    tlp: AMBER
  - type: domain
    value: microsoft-support-sso[.]net
    context: SSO phishing domain used in Scattered Spider campaigns
    expires: 2026-08-08
    tlp: AMBER
  - type: email
    value: it-helpdesk-noreply@support-okta[.]com
    context: Phishing email sender used in Scattered Spider campaigns
    expires: 2026-08-08
    tlp: AMBER
---

## Executive Summary

Scattered Spider (UNC3944/Oktapus) has shifted from SMS phishing to a sophisticated multi-vector identity attack combining vishing (voice phishing), MFA fatigue (push notification flooding), and EvilGinx2 adversary-in-the-middle proxies. The actor targets helpdesk staff and IT support to bypass MFA and gain Okta admin access. Once in, they register persistent MFA devices and move laterally using VPN credentials. This report triggered hunt H-0036 which confirmed an active Scattered Spider compromise in our environment.

---

## Threat Actor Profile

| Field | Details |
|-------|---------|
| Name | Scattered Spider / UNC3944 / Oktapus |
| Type | Cybercriminal (primarily English-speaking, 18-24 year olds) |
| Motivation | Financial — ransomware deployment, data extortion, SIM swapping |
| Active Since | 2022 |
| Target Sectors | Hospitality, retail, technology, telecommunications |
| Geographic Focus | United States, United Kingdom |

---

## Technical Analysis

### Kill Chain

1. **Reconnaissance** — LinkedIn/social media targeting of helpdesk and IT staff
2. **Vishing** — Calls impersonating employee or IT vendor; pressures helpdesk to reset MFA
3. **MFA Fatigue** — Floods target with Okta push notifications until one is approved
4. **Initial Access** — VPN/Citrix login with stolen credentials + approved MFA push
5. **Persistence** — Registers attacker-controlled MFA device; may use EvilGinx2-captured session token
6. **Lateral Movement** — Accesses Okta admin to elevate privileges; pivots to internal tools
7. **Impact** — Varies: ALPHV/BlackCat ransomware deployment, data extortion, SIM swapping for crypto theft

### MITRE ATT&CK Mapping

| Technique | Name | Notes |
|-----------|------|-------|
| T1621 | MFA Request Generation | Push flood — 10-50 requests over minutes until approved |
| T1566.004 | Spearphishing Voice | Vishing helpdesk or target; impersonates IT/vendor |
| T1078 | Valid Accounts | Credentials from prior phishing or broker purchase |
| T1133 | External Remote Services | VPN/Citrix access post-MFA compromise |
| T1539 | Steal Web Session Cookie | EvilGinx2 captures session tokens bypassing MFA |
| T1556.006 | Multi-Factor Authentication | Registers new MFA device for persistence |
| T1598.004 | Spearphishing Voice | Targets helpdesk specifically for MFA bypass |

### Tools Used

- **EvilGinx2** — Reverse proxy that captures both credentials and session cookies mid-flight
- **Okta Admin Console** — Once admin access obtained, used to disable/modify victim MFA factors
- **ScreenConnect/AnyDesk** — Installed post-access for persistent RMM-based C2
- **Telegram** — Actor coordination channel during active intrusions

---

## Recommended Hunt Actions

- **Primary hunt (H-0036):** MFA push flood (>5 denials) followed by successful auth in <15 min window
- **Secondary hunt:** New MFA device registration within 5 minutes of successful VPN login
- **Behavioral detection:** Successful VPN auth from Tor exit node IP ranges

**Suggested platforms:** Okta logs → Google SecOps (YARA-L), CrowdStrike for post-access behavior

---

## References

- CISA Advisory AA23-243A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-243a
- CrowdStrike Scattered Spider Deep Dive: https://www.crowdstrike.com/blog/scattered-spider-attempts-to-avoid-detection/
- Mandiant UNC3944 Analysis: https://www.mandiant.com/resources/blog/unc3944-targets-saas

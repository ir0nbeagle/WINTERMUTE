---
id: TIR-2026-001
title: "Glassworm: Invisible Unicode Supply Chain Attack"
date: 2026-03-18
analyst: ir0n
tlp: AMBER
priority: Critical
status: hunt-created
linked_hunts:
  - H-0001

threat_actors:
  - name: Glassworm
    type: cybercriminal
    motivation: financial
    sectors: [software-development, open-source, developer-tooling]
    geo: global

techniques:
  - T1195.001
  - T1059.007
  - T1027
  - T1027.010
  - T1552
  - T1528
  - T1071.001

tools:
  - name: Unicode PUA steganography
    category: defense-evasion
    description: Invisible characters in U+FE00-FE0F and U+E0100-E01EF ranges encode payload
  - name: eval(Buffer.from())
    category: execution
    description: Node.js decode-and-eval pattern used to execute hidden payload
  - name: Solana RPC API
    category: c2
    description: api.mainnet-beta.solana.com used as C2 channel, blends with legitimate crypto traffic

iocs:
  - type: domain
    value: api.mainnet-beta.solana.com
    context: C2 channel for second-stage payload delivery
    expires: 2026-09-18
    tlp: AMBER
  - type: package
    value: "@aifabrix/miso-client"
    version: "4.7.2"
    context: Malicious npm package published 2026-03-12
    tlp: WHITE
  - type: package
    value: "@iflow-mcp/watercrawl-watercrawl-mcp"
    version: "1.3.0"
    context: Malicious npm package published 2026-03-12
    tlp: WHITE
  - type: filename
    value: quartz.quartz-markdown-editor
    version: "0.3.0"
    context: Malicious VS Code extension published 2026-03-12
    tlp: WHITE
  - type: regex
    value: 'eval\(Buffer\.from\('
    context: Decode-and-eval pattern in malicious JS — hunt behavioral indicator
    tlp: WHITE
  - type: unicode-range
    value: "U+FE00-U+FE0F"
    context: Variation Selectors used as invisible payload carrier
    tlp: WHITE
---

## Executive Summary

Glassworm is a financially motivated supply chain threat actor that injects malicious payloads into open-source software using invisible Unicode characters. Between March 3–12, 2026, the actor compromised 151+ GitHub repositories, multiple npm packages, and at least one VS Code marketplace extension. The hidden payload executes via `eval()` in Node.js and exfiltrates credentials and tokens to a Solana blockchain-based C2 channel.

**Risk to organization:** High. Developer endpoints and CI/CD systems running `npm install` from compromised packages are at risk of credential theft, including npm tokens, GitHub PATs, SSH keys, and browser-stored credentials.

---

## Threat Actor Profile

| Field | Details |
|-------|---------|
| Name | Glassworm |
| Type | Cybercriminal |
| Motivation | Financial — cryptocurrency theft, credential harvesting |
| Active Since | March 2025 (escalated March 2026) |
| Target Sectors | Software development, open-source ecosystem, developer tooling |
| Geographic Focus | Global |

---

## Technical Analysis

### Kill Chain

1. Glassworm injects invisible Unicode PUA characters into legitimate GitHub repositories and npm packages
2. Characters are invisible in code review, IDEs (including VS Code), and diff views
3. Characters decode to a JavaScript payload passed to `eval(Buffer.from(decoded).toString('utf-8'))`
4. Second-stage payload is fetched from a Solana RPC endpoint (appears as legitimate crypto traffic)
5. Payload exfiltrates `.env`, `.npmrc`, SSH keys, and browser credentials to actor infrastructure

### MITRE ATT&CK Mapping

| Technique | Name | Notes |
|-----------|------|-------|
| T1195.001 | Supply Chain Compromise: Software Dependencies | Compromised npm packages and VS Code extensions |
| T1059.007 | JavaScript | eval() execution in Node.js |
| T1027 | Obfuscated Files or Information | Invisible Unicode steganography |
| T1027.010 | Command Obfuscation | Unicode in source hides payload from code review |
| T1552 | Unsecured Credentials | .env, .npmrc, SSH key exfiltration |
| T1528 | Steal Application Access Token | npm tokens, GitHub PATs |
| T1071.001 | Application Layer Protocol: Web | Solana RPC as C2 |

### Tools Used

- **Unicode PUA steganography** — payload carrier, invisible to reviewers
- **eval(Buffer.from())** — Node.js decode-and-eval execution pattern
- **Solana RPC API** — C2 channel (api.mainnet-beta.solana.com)

---

## Recommended Hunt Actions

> These items form the basis for the hunt ticket. Analyst creating the hunt should reference this report as source.

- **Primary hunt:** Node.js processes making DNS/network requests to Solana RPC endpoints (`api.mainnet-beta.solana.com`) — especially on non-Solana development machines
- **Secondary hunt:** Node.js or VS Code Extension Host reading credential files (`.npmrc`, `.env`, `id_rsa`, browser credential stores)
- **Package audit:** Scan developer fleet for presence of `@aifabrix/miso-client@4.7.2` and `@iflow-mcp/watercrawl-watercrawl-mcp@1.3.0`
- **Extension audit:** Check VS Code installations for `quartz.quartz-markdown-editor@0.3.0`
- **Behavioral detection:** `eval(Buffer.from(` pattern in recently installed npm packages

**Suggested platforms:** CrowdStrike Falcon LogScale, Google SecOps UDM

---

## References

- https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode
- https://socket.dev/blog/invisible-unicode-supply-chain-attack

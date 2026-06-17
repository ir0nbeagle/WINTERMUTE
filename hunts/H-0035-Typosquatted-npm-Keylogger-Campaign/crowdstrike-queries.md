# CrowdStrike Falcon — H-0035 Typosquatted npm Keylogger

## Query 1: Long-Running Node Process with Periodic Outbound Connections
```
index=main event_simpleName=NetworkConnectIP4
| where ImageFileName MATCHES "node(\.exe)?"
| where NOT DomainName MATCHES "(npmjs\.com|nodejs\.org|github\.com|cloudflare\.com)"
| stats count as connections, dc(RemoteIP) as unique_ips by ComputerName, ImageFileName, DomainName
| where connections > 10
| sort -connections
```

## Query 2: npm Postinstall Spawning Encoded Command
```
index=main event_simpleName=ProcessRollup2
| where ParentBaseFileName MATCHES "node"
| where CommandLine MATCHES "atob\(|Buffer\.from.*base64|eval\("
| table _time, ComputerName, UserName, ParentBaseFileName, CommandLine
```

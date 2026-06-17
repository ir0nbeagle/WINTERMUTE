# CrowdStrike Falcon — H-0038 Akira Ransomware RMM Abuse

## Query 1: Unauthorized RMM Installation Outside Business Hours
```
index=main event_simpleName=ProcessRollup2
| where CommandLine MATCHES "(anydesk|splashtop|atera|screenconnect|teamviewer).*\.msi"
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| where NOT UserName MATCHES "^(svc-|IT-|admin)"
| table _time, ComputerName, UserName, CommandLine
```

## Query 2: RMM Outbound Connections
```
index=main event_simpleName=NetworkConnectIP4
| where DomainName MATCHES "(anydesk\.com|splashtop\.com|atera\.com|screenconnect\.com)"
| where NOT ComputerName MATCHES "IT-"
| table _time, ComputerName, UserName, ImageFileName, DomainName, RemoteIP
```

## Query 3: Defender Disabled via Registry
```
index=main event_simpleName=RegGenericValueSet
| where RegKeyPath MATCHES "SOFTWARE\\Policies\\Microsoft\\Windows Defender"
| where RegValueName="DisableAntiSpyware" AND RegValueData="1"
| table _time, ComputerName, UserName, RegKeyPath
```

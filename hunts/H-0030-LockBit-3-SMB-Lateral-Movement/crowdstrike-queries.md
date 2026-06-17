# CrowdStrike Falcon — H-0030 LockBit SMB Lateral Movement

## Query 1: SMB Fan-Out — Single Host to Many Targets
```
index=main event_simpleName=NetworkConnectIP4
| where RemotePort=445
| where NOT ImageFileName MATCHES "(svchost|System)"
| stats dc(RemoteIP) as unique_targets by ComputerName, ImageFileName, _time span=1h
| where unique_targets > 10
| sort -unique_targets
```

## Query 2: VSS Deletion
```
index=main event_simpleName=ProcessRollup2
| where CommandLine MATCHES "vssadmin.*delete.*shadow"
    OR CommandLine MATCHES "wmic.*shadowcopy.*delete"
| table _time, ComputerName, UserName, CommandLine
```

## Query 3: Remote Service Creation via PsExec
```
index=main event_simpleName=ServiceInstalled
| where ImagePath MATCHES "\\PSEXEC" OR ServiceName MATCHES "^PSEXE"
| table _time, ComputerName, ServiceName, ImagePath
```

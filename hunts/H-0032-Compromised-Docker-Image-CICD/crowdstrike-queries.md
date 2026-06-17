# CrowdStrike Falcon — H-0032 Compromised Docker Image CI/CD

## Query 1: Container Process Outbound to Non-Whitelisted IP
```
index=main event_simpleName=NetworkConnectIP4
| where ContainerID != ""
| where NOT RemoteIP MATCHES "^(10\.|172\.|192\.168\.)"
| where RemotePort IN (80, 443, 4444, 8080, 8443)
| table _time, ComputerName, ContainerID, ContainerImage, ImageFileName, RemoteIP, RemotePort
| sort -_time
```

## Query 2: Shell Execution on Container Startup
```
index=main event_simpleName=ProcessRollup2
| where ContainerID != ""
| where ImageFileName MATCHES "(/bash|/sh|/dash)"
| where ParentBaseFileName IN ("containerd-shim", "runc", "docker")
| table _time, ContainerID, ContainerImage, CommandLine
```

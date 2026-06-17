# CrowdStrike Falcon — H-0029 TeamPCP PyPI AI/ML Supply Chain

## Query 1: pip Spawning Python Child with Outbound Connection
```
index=main event_simpleName=NetworkConnectIP4
| where ParentBaseFileName = "pip" OR ParentBaseFileName = "pip3"
| where RemotePort IN (80, 443)
| where NOT RemoteIP MATCHES "^(151\.101\||185\.199\||140\.82\|)"
| table _time, ComputerName, UserName, ImageFileName, CommandLine, RemoteIP, RemotePort
| sort -_time
```

## Query 2: Python Reading AI Provider Config Files
```
index=main event_simpleName=FileOpenInfo
| where ImageFileName MATCHES "python"
| where TargetFileName MATCHES "(\.openai|\.anthropic|\.huggingface|\.aws/credentials|\.config/gcloud)"
| table _time, ComputerName, UserName, ImageFileName, TargetFileName
| sort -_time
```

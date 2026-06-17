# CrowdStrike Falcon — H-0033 BlackCat Credential Harvesting

## Query 1: Non-System Process Accessing LSASS
```
index=main event_simpleName=ProcessRollup2
| where TargetProcessName MATCHES "lsass\.exe"
| where NOT ImageFileName MATCHES "(MsMpEng|csrss|winlogon|werfault|taskmgr|CrowdStrike)"
| table _time, ComputerName, UserName, ImageFileName, CommandLine, TargetProcessName
```

## Query 2: SAM Hive Export
```
index=main event_simpleName=ProcessRollup2
| where CommandLine MATCHES "reg.*save.*HKLM\\SAM"
    OR CommandLine MATCHES "reg.*save.*HKLM\\SYSTEM"
| table _time, ComputerName, UserName, CommandLine
```

## Query 3: comsvcs Minidump
```
index=main event_simpleName=ProcessRollup2
| where CommandLine MATCHES "comsvcs" AND CommandLine MATCHES "MiniDump"
| table _time, ComputerName, UserName, CommandLine
```

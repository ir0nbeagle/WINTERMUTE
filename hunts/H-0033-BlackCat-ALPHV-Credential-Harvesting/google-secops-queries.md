# Google SecOps — H-0033 BlackCat Credential Harvesting

## Query 1: LSASS Access from Suspicious Process
```
metadata.event_type = "PROCESS_OPEN"
target.process.file.full_path = /lsass\.exe/
NOT principal.process.file.full_path = /(MsMpEng|csrss|winlogon)/
```

## Query 2: SAM Registry Hive Export
```
metadata.event_type = "PROCESS_LAUNCH"
target.process.command_line = /reg.*save.*HKLM.SAM/
```

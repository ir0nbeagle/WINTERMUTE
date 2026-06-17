# Google SecOps — H-0030 LockBit SMB Lateral Movement

## Query 1: SMB Fan-Out Detection
```
metadata.event_type = "NETWORK_CONNECTION"
target.port = 445
NOT principal.process.file.full_path = "/svchost.exe"
```

## Query 2: Shadow Copy Deletion
```
metadata.event_type = "PROCESS_LAUNCH"
(target.process.command_line = /vssadmin.*delete/ OR
 target.process.command_line = /shadowcopy.*delete/)
```

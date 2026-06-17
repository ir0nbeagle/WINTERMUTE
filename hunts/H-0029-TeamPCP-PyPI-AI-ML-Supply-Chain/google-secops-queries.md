# Google SecOps — H-0029 TeamPCP PyPI AI/ML Supply Chain

## Query 1: pip Child Process Network Connection
```
metadata.event_type = "NETWORK_CONNECTION"
principal.process.parent_process.file.full_path /= "pip"
NOT target.ip = "151.101.*"
NOT target.ip = "185.199.*"
```

## Query 2: Python Reading Credential Config Files
```
metadata.event_type = "FILE_OPEN"
principal.process.file.full_path /= "python"
(target.file.full_path = "/.openai" OR
 target.file.full_path = "/.anthropic" OR
 target.file.full_path = "/.aws/credentials")
```

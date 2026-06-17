# Google SecOps — H-0032 Compromised Docker Image CI/CD

## Query 1: Container Outbound Network Connection
```
metadata.event_type = "NETWORK_CONNECTION"
principal.resource.type = "CONTAINER"
NOT target.ip = /^10\.|^172\.|^192\.168\./
```

## Query 2: Shell Spawned from Container Runtime
```
metadata.event_type = "PROCESS_LAUNCH"
principal.resource.type = "CONTAINER"
target.process.file.full_path = /\/bash|\/sh$/
```

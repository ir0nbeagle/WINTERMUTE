# Google SecOps — H-0035 Typosquatted npm Keylogger

## Query 1: Node.js Periodic External Connections
```
metadata.event_type = "NETWORK_CONNECTION"
principal.process.file.full_path = /node/
NOT target.hostname = /npmjs|nodejs\.org|github/
```

## Query 2: Encoded Payload Execution
```
metadata.event_type = "PROCESS_LAUNCH"
target.process.command_line = /atob\(|Buffer\.from.*base64|eval\(/
```

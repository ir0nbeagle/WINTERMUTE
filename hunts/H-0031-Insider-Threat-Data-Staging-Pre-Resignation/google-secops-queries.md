# Google SecOps — H-0031 Insider Threat Data Staging

## Query 1: Archive Utility Creating Large Files
```
metadata.event_type = "FILE_CREATION"
principal.process.file.full_path = /7z|zip|tar/
target.file.size > 209715200
```

## Query 2: Large Transfer to Personal Cloud
```
metadata.event_type = "NETWORK_CONNECTION"
(target.hostname = /dropbox|drive\.google|onedrive/ OR
 target.domain = /box\.com|wetransfer/)
network.sent_bytes > 104857600
```

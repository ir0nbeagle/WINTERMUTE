# Google SecOps — H-0037 Insider Cloud Storage Exfil

## Query 1: Research VLAN Upload to Personal Cloud
```
metadata.event_type = "NETWORK_CONNECTION"
principal.ip = /^10\.20\./
(target.hostname = /mega\.nz|mediafire|gofile/ OR
 target.domain = /mega\.co\.nz/)
network.sent_bytes > 1048576
```

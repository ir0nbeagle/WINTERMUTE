# CrowdStrike Falcon — H-0031 Insider Threat Data Staging

## Query 1: Large Archive Creation in User Directories
```
index=main event_simpleName=FileWritten
| where ImageFileName MATCHES "(7z\.exe|zip\.exe|tar\.exe|winzip)"
| where TargetFileName MATCHES "(Downloads|Desktop|Documents|AppData\\Local\\Temp)"
| where FileSizeBytes > 209715200
| table _time, ComputerName, UserName, ImageFileName, TargetFileName, FileSizeBytes
| sort -FileSizeBytes
```

## Query 2: Bulk Upload to Cloud Storage
```
index=main event_simpleName=NetworkConnectIP4
| where DomainName MATCHES "(dropbox\.com|drive\.google\.com|onedrive\.live\.com|box\.com|wetransfer\.com)"
| stats sum(BytesSent) as total_bytes by ComputerName, UserName, DomainName, _time span=1h
| where total_bytes > 104857600
| sort -total_bytes
```

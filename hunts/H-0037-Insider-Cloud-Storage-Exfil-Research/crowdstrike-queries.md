# CrowdStrike Falcon — H-0037 Insider Cloud Storage Exfil

## Query 1: Uploads to Personal Cloud Storage from Research VLAN
```
index=main event_simpleName=NetworkConnectIP4
| where DomainName MATCHES "(mega\.nz|mega\.co\.nz|mediafire|anonfiles|gofile\.io)"
| where local_ip MATCHES "^10\.20\."
| stats sum(BytesSent) as total_bytes by ComputerName, UserName, DomainName
| sort -total_bytes
```

## Query 2: Large File Access from S3 Buckets Pre-Staging
```
index=cloudtrail eventName=GetObject
| where userIdentity.type="IAMUser"
| stats count as downloads, sum(bytesTransferredOut) as bytes
    by userIdentity.userName, requestParameters.bucketName
| where bytes > 52428800
| sort -bytes
```

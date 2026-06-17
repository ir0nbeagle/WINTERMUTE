# CrowdStrike Falcon — H-0034 Insider OAuth Token Abuse

## Query 1: Okta Token Generation Outside VPN
```
index=okta eventType=token.grant
| where NOT client.ipAddress MATCHES "^(10\.|172\.16\.|192\.168\.)"
| stats count as token_count by actor.displayName, client.ipAddress, target{}.displayName
| where token_count > 5
| sort -token_count
```

## Query 2: Offboarded Account Activity
```
index=okta
| where actor.displayName IN [offboarded_users_list]
| where eventType IN ("user.session.start", "token.grant", "app.oauth2.token.grant")
| table _time, actor.displayName, client.ipAddress, target{}.displayName, eventType
```

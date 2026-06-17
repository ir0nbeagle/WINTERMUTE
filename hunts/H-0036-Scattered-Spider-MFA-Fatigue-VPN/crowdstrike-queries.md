# CrowdStrike Falcon — H-0036 Scattered Spider MFA Fatigue

## Query 1: MFA Push Flood Followed by Success (Okta)
```
index=okta eventType=system.push.send_factor_verify_push
| stats count as push_count, values(outcome.result) as outcomes
    by actor.displayName, client.ipAddress
| where push_count > 5 AND outcomes MATCHES "SUCCESS"
| sort -push_count
```

## Query 2: New MFA Device Registration Post-Login
```
index=okta eventType IN (user.mfa.factor.activate, user.mfa.factor.update)
| join type=inner actor.displayName [
    search index=okta eventType=user.session.start
    | where _time > relative_time(now(), "-15m")
]
| table _time, actor.displayName, client.ipAddress, target{}.displayName
```

# Google SecOps — H-0034 Insider OAuth Token Abuse

## Query 1: OAuth Token Grant from External IP
```
metadata.event_type = "USER_RESOURCE_ACCESS"
metadata.product_name = "Okta"
security_result.action = "ALLOW"
network.http.user_agent = /oauth/
NOT principal.ip = /^10\.|^172\.16\.|^192\.168\./
```

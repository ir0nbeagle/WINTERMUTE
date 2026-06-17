# Google SecOps — H-0036 Scattered Spider MFA Fatigue

## YARA-L Detection Rule
```
rule scattered_spider_mfa_fatigue {
  meta:
    author = "ir0n"
    description = "MFA push flood followed by approval from new IP"
    severity = "CRITICAL"
    mitre_attack_tactic = "Credential Access"
    mitre_attack_technique = "T1621"

  events:
    $mfa_deny.metadata.event_type = "USER_UNCATEGORIZED"
    $mfa_deny.metadata.product_name = "Okta"
    $mfa_deny.security_result.action = "BLOCK"
    $mfa_deny.principal.user.userid = $user

    $mfa_success.metadata.event_type = "USER_LOGIN"
    $mfa_success.metadata.product_name = "Okta"
    $mfa_success.security_result.action = "ALLOW"
    $mfa_success.principal.user.userid = $user

  match:
    $user over 15m

  condition:
    #mfa_deny > 5 and $mfa_success
}
```

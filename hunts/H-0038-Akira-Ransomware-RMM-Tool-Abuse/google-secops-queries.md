# Google SecOps — H-0038 Akira Ransomware RMM Abuse

## YARA-L Detection Rule
```
rule akira_rmm_abuse {
  meta:
    author = "ir0n"
    description = "Unauthorized RMM tool installation outside business hours"
    severity = "CRITICAL"
    mitre_attack_tactic = "Command and Control"
    mitre_attack_technique = "T1219"

  events:
    $rmm_install.metadata.event_type = "PROCESS_LAUNCH"
    $rmm_install.target.process.command_line = /anydesk|splashtop|atera/
    $rmm_install.target.process.command_line = /\.msi/
    NOT $rmm_install.principal.user.userid = /^(svc-|IT-|admin)/
    $rmm_install.metadata.event_timestamp.seconds > 0

  condition:
    $rmm_install
}
```

## Query 2: Windows Defender Registry Disable
```
metadata.event_type = "REGISTRY_MODIFICATION"
target.registry.registry_key = /Windows Defender/
target.registry.registry_value_name = "DisableAntiSpyware"
target.registry.registry_value_data = "1"
```

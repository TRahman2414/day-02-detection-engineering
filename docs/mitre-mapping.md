# MITRE ATT&CK Mapping

Tags use the Sigma ATT&CK namespace: `attack.<lowercase-hyphenated-tactic>` and `attack.t####[.###]`. Technique tags are candidate behavioral mappings; a single failed-authentication event does not by itself establish brute force.

| Rule | Tactic | Technique | Mapping rationale and limit |
|---|---|---|---|
| Suspicious Encoded PowerShell Execution | Execution; Defense Evasion | [T1059.001](https://attack.mitre.org/techniques/T1059/001/); [T1027](https://attack.mitre.org/techniques/T1027/) | PowerShell is the interpreter; encoded command content may provide obfuscation. Encoding alone is not proof of maliciousness. |
| Windows Defender Protection Disabled | Defense Evasion | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Process command lines match attempts to weaken Defender settings. This event does not prove the setting changed successfully. |
| Windows Failed Logon Event | Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/) | The event is a building block for brute-force detection. Alert on a correlated burst, not an isolated 4625. |
| User Added to Privileged Local Group | Persistence; Privilege Escalation | [T1098.007](https://attack.mitre.org/techniques/T1098/007/) | A member is added to a local group. The rule is limited to selected privileged group names. |
| Suspicious Scheduled Task Creation | Persistence; Execution | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Event 4698 task content contains selected interpreters or suspicious paths; benign automation is common. |
| New Windows Service Creation | Persistence; Privilege Escalation | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | System Event 7045 records service installation. It does not assess the service binary or prove maliciousness. |
| Failed SSH Authentication Event | Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/) | A single failure is not brute force. Correlation by source address, account, or host is needed. |
| Linux Shell History Clearing | Defense Evasion | [T1070.003](https://attack.mitre.org/techniques/T1070/003/) | History clear, delete, and truncate command lines correspond to command-history clearing. Shell built-ins may not be visible to process telemetry. |
| Sudo Authentication Failure Event | Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/) | An authentication failure is only a signal; repeated events are needed before classifying it as guessing. No Valid Accounts mapping is claimed. |
| Account Discovery on Linux | Discovery | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) | Selected commands query local account or group information. `id` and `groups` also have routine administrative uses. |

The Sigma CLI's bundled ATT&CK catalog does not currently recognize the valid current `defense-evasion` tactic tag or T1562.001, so CI excludes only its `attacktag` validator. Sigma parsing and all other enabled validation checks still run; the mapping references above were checked against the linked MITRE technique pages.

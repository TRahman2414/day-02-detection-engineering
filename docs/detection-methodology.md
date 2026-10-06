# Detection Methodology

## Philosophy

This project follows a simple, repeatable detection engineering lifecycle:

1. **Identify a threat behavior** based on common adversary tactics.
2. **Define the detection logic** in Sigma with a clear logsource and condition.
3. **Map to MITRE ATT&CK** so the detection can be prioritized and reported.
4. **Document telemetry requirements** so operators know what data is needed.
5. **Document false positives** so SOC analysts can tune effectively.
6. **Validate the rule** with automated checks before merging.
7. **Convert to target SIEM** queries for downstream deployment.

## Rule Design Principles

- **Specificity over noise**: Rules target concrete behaviors rather than single events when possible.
- **Platform coverage**: Separate Windows and Linux directories keep rules organized by environment.
- **Experimental status**: All rules are marked `status: experimental` to reflect their portfolio-lab purpose.
- **Readable logic**: Detection sections use clear field names and straightforward conditions.
- **Tunable severity**: Levels are assigned based on likelihood of malicious intent and business context.

## Coverage Areas

| ATT&CK Tactic | Example Detections |
|---|---|
| Execution | Encoded PowerShell execution |
| Persistence | New service creation, scheduled task creation, privileged group changes |
| Privilege Escalation | Sudo failures, privileged group changes |
| Defense Evasion | Windows Defender disabling, shell history clearing |
| Credential Access | Multiple failed Windows logons, multiple failed SSH attempts |
| Discovery | Account discovery commands on Linux |

## Validation Before Deployment

Every rule must pass:

- YAML parsing
- Required metadata checks
- UUID format and uniqueness checks
- MITRE ATT&CK technique tag checks
- False-positive documentation checks
- Severity value checks

Only after passing these checks should a rule be converted to a SIEM query.

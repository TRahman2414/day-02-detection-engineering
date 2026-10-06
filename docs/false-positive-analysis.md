# False-Positive Analysis

Every rule includes a `falsepositives` section in the Sigma file. This document expands on the benign activity that can trigger each detection.

## Windows Detections

### Suspicious Encoded PowerShell Execution

- Legitimate administrators running encoded PowerShell for automation.
- Configuration management tools such as Microsoft SCCM or Intune.
- Security scanners or vulnerability assessment tools that use encoded commands.
- PowerShell-based installers or deployment scripts.

### Windows Defender Protection Disabled

- Authorized IT staff or endpoint tools attempting a documented Defender configuration change.
- Approved security software installation or troubleshooting that invokes the listed switches.
- The rule detects command-line attempts; confirm whether the change succeeded using Defender or registry telemetry.

### Windows Failed Logon Event

- Users repeatedly mistyping passwords, especially after a recent password change.
- Misconfigured services or scripts using stale credentials.
- Domain-joined systems with expired service account passwords.
- Authorized penetration tests or red-team exercises.

### User Added to Privileged Local Group

- Legitimate administrator provisioning new user accounts.
- Configuration management tools updating group membership.
- Help-desk personnel adding users to Remote Desktop Users for support sessions.

### Suspicious Scheduled Task Creation

- Legitimate IT automation and maintenance tasks.
- Software installers creating temporary scheduled tasks.
- Backup or patching tools that schedule recurring jobs.

### New Windows Service Creation

- Legitimate software installation registering services.
- Configuration management tools deploying monitoring agents.
- Administrators installing diagnostic or support services.

## Linux Detections

### Failed SSH Authentication Event

- Users mistyping passwords or using stale SSH keys.
- Automated scripts with outdated credentials.
- Configuration management tools connecting with old keys.
- Authorized penetration testing or red-team exercises.

### Linux Shell History Clearing

- Users intentionally clearing command history for privacy or troubleshooting.
- Approved shell-session cleanup scripts that remove or truncate history files.
- Security response or test activity that clears history as part of an authorized exercise.

### Sudo Authentication Failure Event

- Users mistyping a sudo password once or several times.
- Shared operator accounts or automation running with stale credentials.
- Local PAM or sudo configuration problems that reject otherwise valid requests.

The Sigma rule now requires an authentication-failure phrase; ordinary successful `sudo:` command records are not intended to match.

### Account Discovery on Linux

- System administrators performing routine account audits.
- Configuration management and asset inventory tools.
- Troubleshooting scripts that enumerate users or groups.

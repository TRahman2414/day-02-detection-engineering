# Telemetry Requirements

The rules only work when the specified source is collected and fields are normalized to the names used in the Sigma rule. Availability depends on host configuration, operating-system version, and log pipeline. Optional telemetry improves context but is not silently assumed by the rules.

## Windows detections

### Suspicious Encoded PowerShell Execution

- **Required source/event:** Windows process creation, such as Security 4688 with command-line auditing enabled, or Sysmon Event 1.
- **Required fields:** `Image`, `CommandLine`.
- **Optional enhancement:** PowerShell Operational 4103/4104 for script content and process ancestry from Sysmon or EDR.
- **Limitations:** Script-block logging is not a substitute for the rule's process-creation source. Case handling is backend dependent; encoded commands are not inherently malicious.

### Windows Defender Protection Disabled

- **Required source/event:** Windows process-creation telemetry.
- **Required fields:** `Image`, `CommandLine` containing the listed Defender preference switches.
- **Optional enhancement:** Microsoft-Windows-Windows Defender Operational events and registry auditing for policy-setting changes.
- **Limitations:** The rule matches command-line attempts and cannot prove a setting changed. It does not currently detect Defender event-log state changes or generic registry activity.

### Windows Failed Logon Event

- **Required source/event:** Security Event 4625.
- **Useful fields:** Target username, source address, logon type, host, status/substatus.
- **Optional enhancement:** SIEM aggregation using those fields and the strategy in [`correlation-strategies.md`](correlation-strategies.md).
- **Limitations:** The Sigma rule only matches Event ID 4625. It does not count attempts and may include expected failures, machine accounts, or service activity.

### User Added to Privileged Local Group

- **Required source/event:** Security Event 4732 (member added to a security-enabled local group).
- **Useful fields:** `TargetUserName` (group), member name/SID, subject account, host.
- **Optional enhancement:** Events 4728/4756 for global/universal groups, and change-management or identity context.
- **Limitations:** The rule covers a fixed set of group names and Event 4732 only. Domain-group changes and localized group names need separate handling.

### Suspicious Scheduled Task Creation

- **Required source/event:** Security Event 4698 with task XML included (available on supported Windows versions/configurations).
- **Required fields:** `EventID`, `TaskContent`.
- **Optional enhancement:** Task Scheduler Operational logs and process-creation telemetry for `schtasks.exe` and task actions.
- **Limitations:** Requires task content in the collected event. The rule only catches selected command strings and may miss tasks with indirect or encoded actions.

### New Windows Service Creation

- **Required source/event:** System log, Service Control Manager Event 7045.
- **Useful fields:** Service name, image path, service account, host.
- **Optional enhancement:** Security Event 4697 may provide a second collection path when enabled; correlate it separately from the 7045 rule. Process-creation and signer/hash data add context.
- **Limitations:** This rule intentionally detects only System Event 7045. Security 4697 is not included because it belongs to a different channel. Service installation is often legitimate.

## Linux detections

### Failed SSH Authentication Event

- **Required source/event:** OpenSSH `sshd` auth messages from journald or `/var/log/auth.log` / `/var/log/secure`.
- **Required field:** Normalized `Message` containing `Failed password`, `Invalid user`, or `authentication failure`.
- **Useful fields:** Source address and attempted username extracted from the message.
- **Optional enhancement:** SIEM aggregation by source, account, and host.
- **Limitations:** Message formats vary by OpenSSH distribution/version. The base event does not establish brute force.

### Linux Shell History Clearing

- **Required source/event:** Process execution records that retain `CommandLine`, or shell/audit telemetry able to record shell built-ins and redirections.
- **Required field:** `CommandLine` containing one of the specific clear/delete/truncate patterns.
- **Optional enhancement:** Audit rules for history-file changes, shell session recording, and file integrity monitoring.
- **Limitations:** `history -c` is a shell built-in and may produce no process-execution event. Process telemetry alone may miss it; filenames, shell, and quoting vary.

### Sudo Authentication Failure Event

- **Required source/event:** Auth facility messages from journald or `/var/log/auth.log` / `/var/log/secure`.
- **Required field:** Normalized `Message` containing `authentication failure` or `incorrect password`.
- **Useful fields:** Host, invoking user, terminal, and timestamp.
- **Optional enhancement:** SIEM threshold aggregation by host and user.
- **Limitations:** Do not use generic `sudo:` messages as failures; successful sudo events also contain that text. Log formats differ, and one failure is not evidence of guessing.

### Account Discovery on Linux

- **Required source/event:** Process creation/audit records with `CommandLine` for the selected account-query commands.
- **Useful fields:** Executable, arguments, user, host, parent process, timestamp.
- **Optional enhancement:** Auditd `execve` records, EDR process telemetry, and privileged-file access auditing.
- **Limitations:** Collection of process arguments is not enabled by default everywhere. Commands such as `id` and `groups` are common during routine logins and administration; parsing/quoting can affect substring matching.

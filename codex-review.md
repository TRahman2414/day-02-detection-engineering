# Codex Security & Detection Engineering Review

**Review date:** 2026-10-06  
**Project path:** `.`  
**Review scope:** Local source, tests, documentation, Sigma parser/checker, generated Splunk and Elasticsearch Lucene queries, package installation, and workflow configuration.

## Executive Summary

The ten-rule portfolio project now parses and converts locally. The original implementation had misleading threshold claims, an overbroad sudo match, mixed Windows event channels, inaccurate ATT&CK details, incomplete validation, an editable-install failure, and CI steps that allowed parser/conversion failures. These were corrected. The full local checks pass, including 15 pytest tests and ten query files from each backend.

The Sigma CLI's bundled ATT&CK catalog is stale for the current `defense-evasion` tag and T1562.001. The built-in `attacktag` validator therefore still reports false invalid-tag findings for valid current ATT&CK mappings. CI excludes that one validator; all other enabled Sigma checks fail on issues, and mappings are linked to MITRE's technique pages. No GitHub Actions run or live SIEM testing was performed. This remains an experimental portfolio project, not a production detection package.

## Findings Before Fixes

| ID | Severity | File / location | Problem | Impact | Remediation |
|---|---|---|---|---|---|
| HIGH-01 | HIGH | `.github/workflows/detection-ci.yml`, Sigma/conversion steps | `continue-on-error: true` allowed Sigma parser, plugin, and conversion failures to pass CI. Actions used movable version tags. | Broken or unsafe detection changes could appear green; supply-chain provenance was weaker. | Make these steps required; pin Checkout and Setup Python to immutable SHAs; remove the unnecessary artifact action. |
| MED-01 | MEDIUM | `rules/windows/win_multiple_failed_logons.yml`; `rules/linux/linux_multiple_failed_ssh.yml`; `rules/linux/linux_sudo_failures.yml` | Titles/descriptions claimed multiple attempts while conditions matched single events. | Users could mistake a base event predicate for a brute-force/correlation alert. | Rename as single-event rules, remove unsubstantiated sub-technique tags, and document explicit SIEM group/count/time-window guidance. |
| MED-02 | MEDIUM | `rules/linux/linux_sudo_failures.yml` | The `sudo:` string matched ordinary sudo records, including successful commands. | High false-positive volume and misleading “authentication failure” label. | Match only authentication-failure/incorrect-password message text. |
| MED-03 | MEDIUM | `rules/windows/win_new_service_creation.yml` | Event IDs 7045 (System) and 4697 (Security) were grouped under one Security logsource. | Event 7045 may not be present in that source and the conversion could miss service installs. | Scope this rule to System Event 7045; document Security 4697 as a separate collection path. |
| MED-04 | MEDIUM | `rules/linux/linux_shell_history_clear.yml`; `rules/windows/win_privileged_group_change.yml`; rule ATT&CK tags | History clearing used T1070.004 (file deletion) instead of T1070.003 (clear command history); local group additions used broad T1098/T1078; ATT&CK tactic tags used obsolete underscore spellings. | ATT&CK reporting was imprecise and Sigma taxonomy checking emitted issues. | Use T1070.003, T1098.007, remove unsupported Valid Accounts/guessing mappings, and use current hyphenated tactic tags. |
| LOW-01 | LOW | `scripts/validate_rules.py`; `tests/` | Duplicate YAML keys silently overwrote values; UUID v4 validation forced version bits; metadata checks accepted weak shapes; tests did not assert an expected inventory or documentation coverage. | Invalid rules or empty/incomplete repositories could pass custom checks. | Reject duplicate keys, validate parsed UUID version, check metadata/condition shapes, inventory count, and false-positive guide coverage. |
| LOW-02 | LOW | `pyproject.toml`; `requirements.txt` | `pip install -e .` failed because setuptools auto-discovered data directories as packages. | The documented base install and CI install could not complete. | Declare an empty package/module set, use an SPDX license string, and rerun editable/core/extra installs successfully. |
| LOW-03 | LOW | `scripts/convert_splunk.sh`; `scripts/convert_elastic.sh` | Conversion relied on `sigma` being in `PATH` and only listed destination files after running. | A valid project-local virtual environment could be reported missing; stale/partial output could look complete. | Resolve `SIGMA_BIN`, PATH, or project `.venv`; convert into a temporary directory, verify count and expected names, then copy outputs. |
| INFO-01 | INFORMATIONAL | `docs/telemetry-requirements.md`; `README.md` | Documentation did not consistently distinguish required source/event, optional enrichment, field assumptions, and limitations; “Elasticsearch” output type was imprecise. | Operators could assume default telemetry or deploy a query in the wrong format. | Document per-rule telemetry and explicitly identify Elasticsearch output as Lucene query strings. |

## Detection Rule Review

All ten rules parse in pySigma and convert to both backends. “Conversion PASS” means local text generation only; it does not mean execution against a SIEM.

| Rule | Result | Issues / scope | ATT&CK | Telemetry | False-positive quality | Conversion result |
|---|---|---|---|---|---|---|
| Suspicious Encoded PowerShell Execution | PASS | Process command line must contain `-enc` or `-encodedcommand` and PowerShell image; encoding is not proof of maliciousness. | T1059.001, T1027 | Process creation with Image and CommandLine; Sysmon 1 or audited 4688. | Admin, endpoint-management, and approved security automation cases documented. | Splunk PASS; Elastic Lucene PASS |
| Windows Defender Protection Disabled | PASS | Detects command-line attempts; no assertion that the setting change succeeded. | T1562.001 | Windows process creation; Defender/registry events are optional confirmation. | Approved Defender configuration and troubleshooting documented. | Splunk PASS; Elastic Lucene PASS |
| Windows Failed Logon Event | PASS | Matches one Event 4625; no aggregation in Sigma. | T1110 candidate mapping; threshold needed | Security 4625; source, target, logon type useful for correlation. | Password mistakes, stale services, authorized testing documented. | Splunk PASS; Elastic Lucene PASS |
| User Added to Privileged Local Group | PASS | Event 4732 and selected local group names; localized names/domain groups need separate coverage. | T1098.007 | Windows Security 4732 with group/member/subject fields. | Admin provisioning, configuration management, help desk documented. | Splunk PASS; Elastic Lucene PASS |
| Suspicious Scheduled Task Creation | PASS | Event 4698 AND selected task-content patterns; not every suspicious task is covered. | T1053.005 | Security 4698 with TaskContent; confirm event version/collection. | Maintenance, deployment, backup tools documented. | Splunk PASS; Elastic Lucene PASS |
| New Windows Service Creation | PASS | System Event 7045 only; Security 4697 is intentionally separate. | T1543.003 | System/Service Control Manager 7045; service name, path, account useful. | Software install, endpoint agents, admin tools documented. | Splunk PASS; Elastic Lucene PASS |
| Failed SSH Authentication Event | PASS | One auth message; message parsing and count correlation are environment-specific. | T1110 candidate mapping; threshold needed | sshd auth log/journald with normalized Message; source/account should be parsed. | Mistyped credentials, stale automation, authorized testing documented. | Splunk PASS; Elastic Lucene PASS |
| Linux Shell History Clearing | PASS | Specific clear/delete/truncate commands; shell built-ins can evade process telemetry. | T1070.003 | Process arguments plus shell/audit telemetry for built-ins and redirection. | User privacy, cleanup, and authorized response cases documented. | Splunk PASS; Elastic Lucene PASS |
| Sudo Authentication Failure Event | PASS | Requires failure phrases, avoiding generic successful `sudo:` events; no threshold. | T1110 candidate mapping; threshold needed | Auth facility Message with host/user; message parsing varies. | Mistyped passwords, shared accounts, PAM issues documented. | Splunk PASS; Elastic Lucene PASS |
| Account Discovery on Linux | PASS | Selected account/group commands; substring matching on `id`/`groups` may be noisy. | T1087.001 | Process/audit CommandLine, user, host, parent process. | Audits, inventory, and troubleshooting documented. | Splunk PASS; Elastic Lucene PASS |

## Bugs Fixed

- Converted the three failed-auth rules into accurately named single-event detections and removed claims that the Sigma condition performs counting.
- Added [`docs/correlation-strategies.md`](docs/correlation-strategies.md) with starting thresholds and group-by fields for Windows 4625, SSH, and sudo events.
- Narrowed sudo matching to authentication-failure phrases; removed the generic `sudo:` match.
- Corrected service creation telemetry to System Event 7045 and documented 4697 separately.
- Narrowed Defender detection to command-line attempts, removing generic Defender path references.
- Removed overly broad encoded-PowerShell variants and reduced Linux shell-history patterns that matched ordinary file references or `/dev/null` redirection.
- Removed broad `who`, `w`, `last`, and `lastlog` substrings from account discovery.
- Made converter scripts work with `SIGMA_BIN`, the current PATH, or the project `.venv`; validate expected output files before copying them into `output/`.
- Added secret/private-key, cache, and virtual-environment ignore patterns without excluding rules or documentation.

## MITRE ATT&CK Corrections

- Local privileged-group addition now uses T1098.007, Additional Local or Domain Groups. T1078 was removed because adding a group member does not itself detect Valid Accounts use.
- Shell history clearing now maps to T1070.003, Clear Command History, instead of T1070.004, File Deletion.
- Removed T1110.001 Password Guessing and T1110.003 Password Spraying from single-event detections. T1110 remains a candidate mapping for a correlated burst only.
- Removed T1078 from sudo failures; one authentication failure does not establish use of a valid account.
- Updated tactic tag spelling to Sigma's current hyphenated taxonomy (for example `attack.defense-evasion`).
- Updated [`docs/mitre-mapping.md`](docs/mitre-mapping.md) and linked the technique pages for review.

## Sigma Corrections

- Corrected `logsource` for Windows service installation to `product: windows`, `service: system`, Event ID 7045.
- Added explicit Linux `Message|contains` predicates for SSH and sudo failures.
- Reduced false-positive-prone shell history and account-discovery matching.
- Confirmed all ten rule files parse and convert. Strict Sigma check passes with all enabled validators and zero issues when excluding the stale built-in `attacktag` validator. Without that exclusion, the installed catalog reports four `InvalidATTACKTagIssue` findings for current `defense-evasion`/T1562.001 tags; this limitation is exposed here and in the docs.

## Python Fixes

- Added a safe YAML loader that rejects duplicate keys.
- Corrected UUID v4 validation to inspect the parsed UUID version rather than asking the parser to rewrite version bits.
- Validate non-empty metadata types, ISO date values, logsource/detection mappings, non-empty conditions, useful false-positive descriptions, valid ATT&CK tactic syntax, and technique-tag syntax.
- Metadata/ATT&CK scripts now fail if no rules are found.
- Added tests for the ten-rule inventory, conditions, duplicate YAML keys, and full false-positive guide coverage.

## CI/CD Security Fixes

- Preserved `permissions: contents: read`, `push`/`pull_request` only, no secrets, no `pull_request_target`, and no generated-file commits.
- Pinned `actions/checkout` v4.4.0 to `11d5960a326750d5838078e36cf38b85af677262` and `actions/setup-python` v5.6.0 to `a26af69be951a213d495a4c3e4e4022e16d87065`.
- Removed `continue-on-error`; tests, custom validators, Sigma checks, and both conversions now fail the job on errors.
- Installs the project plus pinned Sigma CLI/backend packages in one step. The unused upload-artifact action was removed.
- CI workflow syntax was inspected locally; it has not been run by GitHub Actions.

## Dependency Review

- Direct runtime/test dependencies are pinned in `pyproject.toml`: PyYAML 6.0.3 and pytest 9.1.1.
- Optional conversion dependencies are pinned: Sigma CLI 3.1.0, Splunk backend 2.1.0, and Elasticsearch backend 2.1.1.
- `requirements.txt` installs the base project; `pip install -e ".[sigma]"` installs converter extras.
- Editable base installation, optional-extra installation, and requirements installation all succeeded locally. Transitive dependency versions are constrained by upstream package ranges but are not captured in a lock file.

## Splunk Conversion

**PASS — 10/10 rule queries generated** in `output/splunk/` with `pysigma-backend-splunk==2.1.0`. The rules convert to SPL text. No live Splunk instance was used.

## Elasticsearch Conversion

**PASS — 10/10 Lucene query strings generated** in `output/elastic/` with `pysigma-backend-elasticsearch==2.1.1`. The backend target is Lucene; these files are not Elasticsearch Query DSL or ES|QL. No live Elasticsearch cluster was used.

## Test Results

- `python -m pytest -v`: **16 passed** (Python 3.14.7, pytest 9.1.1).
- `python scripts/validate_rules.py`: **PASS**, 10 rules checked.
- `python scripts/check_metadata.py`: **PASS**.
- `python scripts/check_attack_tags.py`: **PASS**.
- `sigma check --exclude attacktag --fail-on-issues rules/`: **PASS**, zero errors, condition errors, or enabled issues.
- `bash -n scripts/convert_splunk.sh scripts/convert_elastic.sh`: **PASS**.
- `pip install -e .`, `pip install -e ".[sigma]"`, and `pip install -r requirements.txt`: **PASS**.
- Both conversion scripts ran with no virtual-environment activation and produced ten files each.

## Remaining Limitations

- ATT&CK automatic validation is limited by the installed Sigma catalog; CI excludes its `attacktag` validator. The project's own check validates tag shape, not live ATT&CK catalog membership.
- Correlation thresholds are documentation only. The converted queries are single-event predicates and require SIEM-specific aggregation for multi-event alerts.
- No sample event fixtures, Windows/Linux host telemetry, deployed Splunk/Elasticsearch, or GitHub Actions run were available.
- Local test execution used Python 3.14.7. CI is configured for Python 3.12 but was not executed on GitHub.
- The project folder is not a Git checkout, so repository status, staged changes, and a source-control diff could not be inspected.
- Direct dependencies are pinned, but transitive dependencies are not frozen.

## Production Readiness

This is an **experimental portfolio Detection-as-Code project**. Local YAML/Sigma checks and query generation do not establish detection efficacy, telemetry coverage, alert quality, or production readiness.

## Final Assessment

**READY FOR GITHUB** as a clearly labeled experimental portfolio project, with the documented ATT&CK validator/catalog limitation and without production-readiness claims. GitHub Actions and live SIEM behavior still require external execution to verify.

# Lessons Learned

## Detection Design

- A Sigma event predicate is not an event-count correlation. Failed-logon and failed-auth rules remain single-event detections; their threshold strategy is documented separately.
- Field names do not guarantee telemetry availability. Event channels, audit settings, process argument collection, and parsing need to be confirmed in the deployment environment.
- ATT&CK mappings should follow the behavior actually observed. Local-group changes map to T1098.007; shell-history clearing maps to T1070.003.

## Engineering

- Reject duplicate YAML keys so one definition cannot silently override another.
- Verify the real rule inventory in tests so an empty or incomplete `rules/` folder cannot pass.
- Generate conversions in a temporary directory and verify each expected output before updating generated query files.
- Keep the distinction between locally generated Lucene/SPL text and a query that has been executed in a live SIEM.

See [`codex-review.md`](../codex-review.md) for the full security and detection review, tested results, and remaining limitations.

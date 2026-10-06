# Failed-Authentication Correlation Strategies

The three matching Sigma rules detect individual events. Their portable conversions do not implement a threshold, grouping, or time window. Configure and tune correlation in the target SIEM after confirming the source fields are populated.

| Base event | Suggested group-by | Starting investigation threshold | Important caveats |
|---|---|---|---|
| Windows Security 4625 | Source IP and/or target account, scoped by host | 5 failures in 5 minutes | Separate network logons from local interactive activity; exclude known service accounts and expected authentication gateways carefully. |
| Linux sshd failure | Source IP and/or attempted username, scoped by host | 5 failures in 5 minutes | Invalid-user messages may not provide the same normalized fields as failed-password messages. Account for NAT, bastions, and internet-facing exposure. |
| sudo authentication failure | Host and invoking user | 3 failures in 5 minutes | Keep authentication-failure messages distinct from ordinary sudo command records. Shared operator accounts can distort attribution. |

These are starting points for a lab, not universally safe thresholds. Tune them against real baseline volume and the organization's account lockout, SSH, and sudo policies. The current Splunk and Elasticsearch conversions contain only the base event predicates; no live SIEM query or alert has been tested.

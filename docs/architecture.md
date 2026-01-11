The SSH brute-force detector analyzes system authentication logs to identify patterns of repeated failed SSH login attempts. 
It parses log entries to extract timestamps, source IP addresses, usernames, and authentication outcomes.

The detector maintains a per-IP sliding time window to count authentication failures and triggers an alert when predefined 
thresholds are exceeded. Pre-authentication negotiation errors are classified separately to avoid false positives.

Alerts may be escalated when a successful login occurs shortly after repeated failures, indicating potential credential compromise.
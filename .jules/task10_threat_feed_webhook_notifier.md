### Task: Real-Time Threat Feed Webhook Dispatcher

#### 1. Architectural Context & Purpose:
The daily ingestion pipeline compiles `feed.atom` and `feed.json`. However, security engineers and DevSecOps teams require active push notifications when new CRITICAL or HIGH severity MCP advisories are detected (e.g. DNS rebinding, prompt injection, RCE in tool execution).
Adding a webhook dispatcher allows publishing real-time alerts to Discord, Slack, or GitHub Discussions whenever new high-severity advisories are cataloged.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/feed.py`: Generates `feed.atom` and `feed.json`.
* `src/mcp_vulnerabilities/pipeline.py`: Ingestion pipeline execution.
* `.github/workflows/daily_sync.yml`: CI trigger location.

#### 3. Implementation Details:
1. Create `src/mcp_vulnerabilities/notifier.py`:
   - Class `ThreatFeedNotifier`:
     - Reads newly ingested advisories from current run (or diffs `feed.json` against prior checkpoint).
     - Filters for severity `CRITICAL` or `HIGH` (`cvss_score >= 7.0`).
     - Formats Discord webhook payload (embed with title, CVSS score, vulnerable tools, and remediation link).
     - Formats Slack incoming webhook payload (blocks with severity indicator and CVE link).
     - Dispatches via `urllib.request` if `DISCORD_WEBHOOK_URL` or `SLACK_WEBHOOK_URL` is set in environment.
2. In `cli.py`:
   - Add flag `--notify-webhooks` to `sync` command.

#### 4. Acceptance Criteria:
- [ ] If webhook URLs are provided, formatted payloads are dispatched for new CRITICAL/HIGH advisories.
- [ ] If webhook URLs are omitted, the step completes silently without error.
- [ ] Unit tests in `tests/test_feed.py` verify payload formatting and filtering logic using mocks.

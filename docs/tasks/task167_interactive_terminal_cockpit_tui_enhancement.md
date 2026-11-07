# Task 167: Interactive Terminal Cockpit TUI Enhancement

## Objective
Fix critical data source disconnections in `src/mcp_vulnerabilities/audit/tui.py` (`McpTuiExplorer`), populate real OSV vulnerability advisories, resolve hardcoded header/status strings, and respect the `--config` CLI argument.

## Background & Issues Identified
- `self.matcher = VulnerabilityMatcher([])` is initialized with an empty list in `tui.py`, causing all scanned servers to report 0 vulnerabilities and display as `[CLEAN]`.
- Header subtitle contains hardcoded literal strings (`OS: platform`, `Posture: Status`).
- `self.args.config` is ignored by the TUI scanner.
- Network scanner results are not surfaced in the server inventory.

## Scope of Changes
1. `src/mcp_vulnerabilities/audit/tui.py`:
   - Load OSV advisories from `data/vulnerabilities` or `vulnerabilities.json.gz` into `VulnerabilityMatcher`.
   - Respect `self.args.config` when present to target specific client configs.
   - Format header subtitle dynamically with `platform.system()` and computed posture metrics (e.g. `⚠️ 1 CRITICAL, 2 HIGH`).
   - Merge active network MCP listeners from `self.net_scanner` into the server list.
2. `tests/audit/test_tui.py`:
   - Add unit tests verifying `McpTuiExplorer` matches real vulnerabilities, handles `--config`, and formats dynamic headers without crashes.

## Acceptance Criteria
- TUI correctly reports vulnerability counts for servers with known CVEs.
- Target config filtering via `--config` restricts inspection to the specified client.
- `pytest tests/audit/test_tui.py` passes 100%.

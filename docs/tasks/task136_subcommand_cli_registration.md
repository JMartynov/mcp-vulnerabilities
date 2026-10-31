# Task 136: Subcommand CLI Registration (`network-scan`, `tui`, `monitor`, `bridge`) (P0)

**Subsystem:** CLI Entrypoint & Parser Infrastructure (`src/mcp_vulnerabilities/cli.py`, `tests/test_acceptance_invariants.py`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave24_empirical_remediation_and_feature_hardening.md](master_plan_wave24_empirical_remediation_and_feature_hardening.md)

---

## 1. Objective & Problem Statement

The platform's unified acceptance test suite in `tests/test_acceptance_invariants.py` specifies an invariant list of 11 core CLI subcommands:
```python
SUBCOMMANDS = [
    "audit", "network-scan", "identify", "proxy", "audit-transitive",
    "audit-typosquat", "verify-feed", "hub", "tui", "monitor", "bridge"
]
```
During the Wave 23 acceptance audit, `test_cli_subcommand_help_invariants` skipped 4 of these 11 subcommands (`network-scan`, `tui`, `monitor`, `bridge`) because invoking `mcp-vuln <subcommand> --help` returned exit code 2 with `invalid choice` in `stderr`. While individual backend modules (such as `src/mcp_vulnerabilities/probe/network_scanner.py` and planned daemon/TUI components) exist or were architected in Waves 21–22, their CLI argument parsers were never formally wired into the primary `argparse` subparsers in `src/mcp_vulnerabilities/cli.py`.

This registration gap produces significant operational friction:
1. Users attempting to execute documented subcommands receive unexpected `invalid choice` errors.
2. Invariant acceptance tests must skip these subcommands instead of validating command line flags and behavior.
3. Automated tools, shell scripts, and CI workflows cannot discover command capabilities via `--help`.

This task resolves the issue by formally registering all four subcommands in `src/mcp_vulnerabilities/cli.py` with complete argument flags, default values, help descriptions, and resilient dispatch handlers.

---

## 2. Detailed Technical Requirements

### 2.1 Subcommand Argument Specifications

In `src/mcp_vulnerabilities/cli.py`, add subparsers for the 4 subcommands:

#### 1. `network-scan`
- **Subparser Name**: `"network-scan"`
- **Help Text**: `"Scan local and network TCP ports for active MCP servers and unauthenticated listeners"`
- **Arguments**:
  - `--target` / `-t` (`str`, default `"127.0.0.1"`): Target IP address or hostname to scan.
  - `--ports` / `-p` (`str`, default `"3000-8800"`): Port range (e.g. `"3000-8800"`, `"8000,8080,8765"`), or `"common"`.
  - `--cidr` (`str`, default `None`): CIDR subnet range for LAN discovery (e.g. `"192.168.1.0/24"`).
  - `--timeout` (`float`, default `1.0`): Connection and probe timeout in seconds per port.
  - `--concurrency` (`int`, default `64`): Maximum concurrent asynchronous socket connections (bounded by `asyncio.Semaphore`).
  - `--format` (`str`, choices `["table", "json"]`, default `"table"`): Output format.
  - `--output` / `-o` (`Path`, default `None`): Optional file path to write results.
- **Handler Dispatch**:
  - Connects to `src/mcp_vulnerabilities/probe/network_scanner.py:run_network_scan()`.

#### 2. `tui`
- **Subparser Name**: `"tui"`
- **Help Text**: `"Launch split-pane curses terminal dashboard for interactive security exploration"`
- **Arguments**:
  - `--config` / `-c` (`Path`, default `None`): Path to specific AI client config file to inspect.
  - `--theme` (`str`, choices `["dark", "light", "high-contrast"]`, default `"dark"`): Terminal color theme.
  - `--no-color` (`bool`, action `"store_true"`): Disable terminal ANSI color output.
- **Handler Dispatch**:
  - Checks `sys.stdin.isatty()`: if running in a non-interactive environment (CI, pipe, or background process), exits cleanly with code `1` and prints `Error: Interactive TUI requires a TTY terminal. Use 'mcp-vuln audit' for headless output.`
  - Dispatches to `src/mcp_vulnerabilities/audit/tui.py:launch_tui()` (or resilient stub if curses is unsupported).

#### 3. `monitor`
- **Subparser Name**: `"monitor"`
- **Help Text**: `"Run background monitoring daemon to continuously detect MCP port drift and config mutations"`
- **Arguments**:
  - `--daemon` (`bool`, action `"store_true"`): Run in background detached daemon mode.
  - `--interval` (`int`, default `300`): Polling interval in seconds (default: 5 minutes).
  - `--config` (`Path`, default `None`): Configuration file or directory to monitor.
  - `--alert-webhook` (`str`, default `None`): Webhook URL (Slack/Discord) for immediate high-severity alerts.
  - `--desktop-notify` (`bool`, action `"store_true"`): Trigger OS desktop notifications on posture drift.
  - `--pid-file` (`Path`, default `~/.mcp-vuln/monitor.pid`): Daemon PID lockfile path.
- **Handler Dispatch**:
  - Dispatches to `src/mcp_vulnerabilities/daemon/monitor.py:start_monitor()` (or resilient stub).

#### 4. `bridge`
- **Subparser Name**: `"bridge"`
- **Help Text**: `"Run secure local loopback bridge server for static web portal workstation scanning"`
- **Arguments**:
  - `--port` (`int`, default `8765`): Local TCP port to bind.
  - `--host` (`str`, default `"127.0.0.1"`): Host address to bind (must be loopback `127.0.0.1` or `::1`).
  - `--cors-origins` (`str`, default `"https://jmartynov.github.io,http://localhost:*,http://127.0.0.1:*"`): Comma-separated list of allowed CORS origins.
  - `--simulate` / `--mock` (`bool`, action `"store_true"`): Run in simulated demonstration mode emitting synthetic progress events.
- **Handler Dispatch**:
  - Dispatches to `src/mcp_vulnerabilities/daemon/bridge.py:run_bridge_server()`.

---

## 3. Invariant Requirements & Verification Plan

### 3.1 CLI Invariants
1. **Zero Invalid Choice Exceptions**:
   - `mcp-vuln network-scan --help` must exit with returncode `0`.
   - `mcp-vuln tui --help` must exit with returncode `0`.
   - `mcp-vuln monitor --help` must exit with returncode `0`.
   - `mcp-vuln bridge --help` must exit with returncode `0`.
2. **Help Text Consistency**:
   - Every registered argument must be clearly documented in the `--help` output.
   - Positional and optional argument conventions must match existing subcommands (`audit`, `proxy`, `hub`).
3. **Loopback Address Validation**:
   - For `bridge`, passing an external interface (e.g. `--host 0.0.0.0` or `--host 192.168.1.50`) must be rejected with exit code `2` and an explicit security warning: `Security error: Bridge daemon must bind to loopback address (127.0.0.1 or ::1).`

### 3.2 Acceptance Test Updates
In `tests/test_acceptance_invariants.py`:
- Remove the skip condition:
  ```python
  # Previously:
  # if "invalid choice" in result.stderr:
  #     pytest.skip(f"Subcommand {subcmd} is not registered in CLI parser yet.")
  ```
- Assert `result.returncode == 0` for all 11 subcommands without any skips.

---

## 4. Deliverables & Integration Checklist

- [ ] Add subparser definitions for `network-scan`, `tui`, `monitor`, and `bridge` in `src/mcp_vulnerabilities/cli.py`.
- [ ] Implement dispatcher handlers in `src/mcp_vulnerabilities/cli.py` wiring to their respective modules with graceful fallback stubs.
- [ ] Update `tests/test_acceptance_invariants.py` to eliminate skip logic for the 4 subcommands.
- [ ] Run `pytest tests/test_acceptance_invariants.py` and verify all tests pass with 0 skips and 0 failures.

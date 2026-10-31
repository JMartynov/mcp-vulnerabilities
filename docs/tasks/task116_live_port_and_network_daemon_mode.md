# Task 116: Live Port & Network Daemon Mode (P0)

**Subsystem:** Background Daemon & Notification Engine (`src/mcp_vulnerabilities/daemon/monitor.py`, `src/mcp_vulnerabilities/cli.py`, `tests/daemon/test_monitor.py`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave22_daemon_sandbox_tui_and_web_bridge.md](master_plan_wave22_daemon_sandbox_tui_and_web_bridge.md)

---

## 1. Objective & Problem Statement

Developers and enterprise engineering teams constantly start, modify, or terminate local microservices, test containers, and AI development servers. In Model Context Protocol (MCP) workflows, an engineer or automation script can spin up an unauthenticated SSE or HTTP JSON-RPC endpoint on localhost or a LAN interface without registering it in an AI client configuration file. These "shadow" MCP servers frequently expose file systems, terminal access, database queries, or private corporate context to any process on the network.

While Wave 21 introduced on-demand network scanning (`network_scanner.py`) and comparative security drift evaluation (`picture_diff.py`), manual command execution leaves a window of vulnerability between scans. 

This task implements a continuous, production-grade **Live Port & Network Monitor Daemon**:
1. Runs in the background as a headless POSIX daemon, macOS `launchd` agent, or Linux `systemd` user service.
2. Periodically executes asynchronous port scans and drift evaluations at a configurable cadence (default: every 300 seconds).
3. Automatically compares discovered endpoints and local AI client configurations against the established `SecurityPicture` baseline (`~/.mcp-vuln/state/security_picture.json`).
4. Dispatches immediate native desktop notifications (macOS `osascript`, Linux `notify-send`) and webhook alerts (Slack, Discord, custom SIEM) when newly vulnerable servers, rogue shadow endpoints, or tool signature tamper events are detected.
5. Employs intelligent alert deduplication and debouncing to prevent notification fatigue while maintaining rigorous security posture visibility.

---

## 2. Detailed Technical Requirements

### 2.1 Daemon Architecture & Process Management (`src/mcp_vulnerabilities/daemon/monitor.py`)

1. **Process Lifecycle & Daemonization**:
   - Class `McpMonitorDaemon`:
     - Initializes with configuration dataclass `MonitorConfig`:
       ```python
       @dataclass
       class MonitorConfig:
           interval_seconds: int = 300
           targets: str = "localhost"
           ports_spec: str = "3000-8800"
           notify_os: bool = False
           webhook_url: str | None = None
           pid_file: Path = Path.home() / ".mcp-vuln" / "run" / "monitor.pid"
           log_file: Path = Path.home() / ".mcp-vuln" / "logs" / "monitor.log"
           baseline_path: Path = Path.home() / ".mcp-vuln" / "state" / "security_picture.json"
           debounce_window_sec: int = 86400  # 24 hours suppression for identical alerts
       ```
   - Double-fork daemonization for `--daemon` mode:
     - Detaches standard file descriptors (`stdin`, `stdout`, `stderr`) and redirects to `log_file`.
     - Writes PID to `pid_file` with an advisory file lock (`fcntl.flock`).
     - Graceful signal handling: registers handlers for `SIGTERM`, `SIGINT`, and `SIGHUP` (reloads baseline picture without terminating daemon).
   - PID management commands:
     - `mcp-vuln monitor --status`: Reads `pid_file`, validates if process is running via `os.kill(pid, 0)`.
     - `mcp-vuln monitor --stop`: Reads `pid_file`, sends `SIGTERM`, waits up to 5 seconds, and removes the PID file.

2. **Service Template Generation**:
   - Provide subcommands or flags to generate native OS service definitions:
     - macOS `launchd`: Generates `~/Library/LaunchAgents/com.mcp-vuln.monitor.plist`.
     - Linux `systemd`: Generates `~/.config/systemd/user/mcp-vuln-monitor.service`.

### 2.2 Periodic Inspection & Drift Evaluation Loop

1. **Asynchronous Execution Engine**:
   - Implements async event loop iteration:
     ```python
     async def run_monitoring_cycle(self) -> SecurityPictureDiff | None:
         # 1. Probe network endpoints across specified port ranges
         endpoints = await self.network_scanner.scan_endpoints(
             targets=self.config.targets,
             ports_spec=self.config.ports_spec
         )
         # 2. Scan universal local AI client configurations
         client_servers = self.client_scanner.scan_all_clients()
         
         # 3. Build live SecurityPicture
         live_picture = SecurityPicture.build_from_scan(
             client_servers=client_servers,
             network_endpoints=endpoints,
             passports_catalog=self.passports
         )
         
         # 4. Compare with approved baseline
         baseline = SecurityPicture.load(self.config.baseline_path)
         if baseline is None:
             # If no baseline exists, save current as initial baseline
             live_picture.save(self.config.baseline_path)
             return None
             
         diff = SecurityPictureDiffer.diff(baseline=baseline, current=live_picture)
         return diff
     ```
2. **Debounce & Deduplication Cache**:
   - Maintains an in-memory and disk-backed fingerprint hash of active alerts (`~/.mcp-vuln/state/alert_cache.json`).
   - If a drift finding (e.g. shadow server on port 8000) was alerted within `debounce_window_sec`, suppress repeated alerts unless its severity escalates (e.g., from `MEDIUM` to `CRITICAL`).

### 2.3 Multi-Channel Notification Dispatcher

1. **Native Desktop Notifications**:
   - macOS:
     ```python
     def send_macos_notification(title: str, message: str, severity: str) -> None:
         sound = "Basso" if severity in ("CRITICAL", "HIGH") else "Submarine"
         script = f'display notification "{message}" with title "{title}" sound name "{sound}"'
         subprocess.run(["osascript", "-e", script], check=False)
     ```
   - Linux:
     ```python
     def send_linux_notification(title: str, message: str, severity: str) -> None:
         urgency = "critical" if severity in ("CRITICAL", "HIGH") else "normal"
         subprocess.run(["notify-send", title, message, f"--urgency={urgency}"], check=False)
     ```
2. **Webhook Integrations**:
   - Slack Incoming Webhooks:
     - Formats rich payload with JSON `blocks`:
       - Header: `🚨 MCP Security Alert: Rogue or Vulnerable Server Detected`
       - Fields: Server Identifier, Target Port, Transport (`SSE`/`stdio`), CVEs & CVSS Scores, Detected Drift Category.
       - Color bar: `#E01E5A` for Critical/High, `#ECB22E` for Warnings.
   - Discord Webhooks:
     - Formats rich `embeds` payload with matching severity colors and timestamps.
   - Generic JSON Webhook:
     - Sends standard JSON payload matching `SecurityPictureDiff.to_dict()` with HMAC signature header `X-MCP-Signature` if configured.

### 2.4 CLI Command Specification (`src/mcp_vulnerabilities/cli.py`)

```text
mcp-vuln monitor [OPTIONS]

Options:
  --daemon                Run as a background daemon process.
  --interval SECONDS      Monitoring interval in seconds (default: 300).
  --targets SPEC          Target host specification (default: localhost).
  --ports SPEC            Port range or list to scan (default: 3000-8800).
  --notify                Enable native desktop notifications (macOS / Linux).
  --webhook URL           Webhook URL for real-time alerts (Slack / Discord).
  --status                Check status of running monitor daemon.
  --stop                  Stop running monitor daemon.
  --install-service       Generate and install OS service (launchd / systemd).
  --log-file PATH         Path to monitor daemon log file.
  --pid-file PATH         Path to monitor daemon PID file.
```

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_116_1 (Clean Daemonization & Signal Trapping):** Daemon correctly forks, releases terminal tty, persists PID file, and cleanly shuts down on `SIGTERM` or `SIGINT` without orphaned threads.
- [ ] **INVARIANT_116_2 (PID File Mutual Exclusion):** Starting a monitor instance when another instance is already running with an active PID file raises an error and refuses to double-spawn.
- [ ] **INVARIANT_116_3 (Stateful Drift Detection Accuracy):** When a new mock server is launched on an inspected port during a monitoring cycle, the daemon triggers a drift alert within `interval_seconds`.
- [ ] **INVARIANT_116_4 (Alert Debouncing & Deduping):** Duplicate drift detections for the same unaltered finding do not fire repetitive desktop or webhook notifications within the 24-hour debounce window.
- [ ] **INVARIANT_116_5 (Fault-Tolerant Webhook Dispatch):** Webhook HTTP timeouts or network failures are caught, logged, and retried with exponential backoff without crashing the core monitoring loop.
- [ ] **INVARIANT_116_6 (OS Notification Non-Blocking):** Invoking `osascript` or `notify-send` does not block or delay the asynchronous monitoring loop if notification services are slow or unavailable.

---

## 4. Deliverables

1. `src/mcp_vulnerabilities/daemon/monitor.py`: Core `McpMonitorDaemon`, `MonitorConfig`, PID file manager, scheduling loop, drift integration, and desktop/webhook alert dispatchers.
2. `src/mcp_vulnerabilities/daemon/__init__.py`: Package initialization exposing daemon components.
3. `src/mcp_vulnerabilities/cli.py`: Subcommand registration for `mcp-vuln monitor` with all configuration flags.
4. `tests/daemon/test_monitor.py`: Comprehensive test suite verifying PID management, cycle execution, debounce logic, desktop notification fallbacks, and webhook payloads.

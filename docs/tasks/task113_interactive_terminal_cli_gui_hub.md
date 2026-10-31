# Task 113: Interactive Terminal CLI GUI Hub (P0)

**Subsystem:** Interactive Terminal Experience (`src/mcp_vulnerabilities/audit/hub.py`, `src/mcp_vulnerabilities/cli.py`, `tests/test_interactive_hub.py`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave21_network_inspection_security_picture_and_cli_hub.md](master_plan_wave21_network_inspection_security_picture_and_cli_hub.md)

---

## 1. Objective & Problem Statement

Command-line security tools often suffer from cognitive overload, forcing developers and security engineers to remember dozens of complex flags (`--format`, `--verify-signatures`, `--save-baseline`, `--cidr`, `--strict-integrity`). Conversely, completely headless tools lack the real-time visual feedback needed during exploratory audits and interactive workstation remediation.

`mcp-fingerprints` set a benchmark with its clean, emoji-anchored, visual interactive command hub. This task brings that exact aesthetic, ease of use, and visual clarity to `mcp-vulnerabilities`:
1. Launches automatically when `mcp-vuln` is executed without arguments in an interactive terminal (TTY), or explicitly via `mcp-vuln hub`.
2. Features a **Dynamic Status Header** presenting live workstation posture, client scan counts (across 17 clients), network listener activity, total discovered servers, baseline snapshot status, and an aggregate security posture badge.
3. Provides a clean 6-category navigation menu covering local workstation auditing, network scanning, stateful drift tracking, vulnerability remediation, and compliance exporting.
4. Manages the terminal cleanly with alternate screen buffers (`\033[?1049h`), strict SIGINT traps, and ANSI escape sanitization to prevent terminal injection attacks.

---

## 2. Detailed Technical Requirements

### 2.1 TTY Auto-Dispatch & Subcommand Registration (`src/mcp_vulnerabilities/cli.py`)

1. Auto-dispatch on zero arguments:
   - In `main()` (`cli.py`), check if `len(sys.argv) == 1`:
     - If `sys.stdin.isatty()` and `sys.stdout.isatty()`: dispatch directly to `run_hub()`.
     - If not a TTY (e.g. running in CI/CD pipeline or script pipe): print CLI help and exit with code `0`.
2. Explicit subcommand:
   - Add `hub` parser to CLI subparsers:
     ```python
     hub_p = subparsers.add_parser("hub", help="Launch interactive terminal CLI hub")
     hub_p.add_argument("--json", action="store_true", help="Non-interactive JSON mode fallback")
     hub_p.add_argument("--batch", action="store_true", help="Batch non-interactive execution")
     ```

### 2.2 Dynamic Status Header Architecture (`src/mcp_vulnerabilities/audit/hub.py`)

Implement `get_dynamic_status_header() -> str`:
1. System Information:
   - Query OS name, version, and architecture: e.g. `macOS 15.3 (arm64)` or `Linux 6.8 (x86_64)`.
2. Local Client Telemetry:
   - Run lightweight config locator across all 17 supported clients:
     - Reports detected count: e.g., `14 / 17 detected`.
3. Network Probing Telemetry:
   - Checks local loopback listeners on default MCP ports (`3000, 3001, 8000, 8080, 8765, 8800`).
4. Server Counts:
   - Aggregates total servers: `X (Y Local Stdio, Z Network SSE/HTTP)`.
5. Baseline Picture Status:
   - Checks `~/.mcp-vuln/state/security_picture.json`:
     - If file exists: `Saved (YYYY-MM-DD HH:MM:SS)`.
     - If absent: `Not initialized`.
6. Aggregate Security Posture Badge:
   - Evaluates confirmed CVE counts and tamper incidents:
     - 🟢 `SECURE (0 vulnerabilities detected)`
     - 🟡 `WARNING (N Medium/High CVEs detected)`
     - 🔴 `CRITICAL (Tamper detected or Critical CVEs)`

Header Visual Template:
```text
================================================================================
                     🛡️  MCP SECURITY COMMAND HUB  🛡️
================================================================================
 OS: {os_info}
 Local Clients Scanned: {clients_detected} / 17 detected
 Network Hosts Probed: {network_summary}
 Total Discovered Servers: {total_servers} ({local_count} Local, {net_count} Network)
 Baseline Picture Status: {baseline_status}
 Security Posture: {posture_badge}
================================================================================
```

### 2.3 Main Menu Hierarchy & Actions

1. `[1] 🖥️  Local Workstation Audit & Shadow MCP Discovery`:
   - Scans all 17 AI client configuration paths and global npm/npx installations.
   - Identifies shadow MCP packages not tracked by formal client configs.
   - Displays color-coded vulnerability audit table with CVE IDs and CVSS scores.
2. `[2] 🌐 Network & Port MCP Scanner`:
   - Interactively prompts user for target host/CIDR (default: `localhost`) and port range (default: MCP common ports).
   - Runs asynchronous scanner with live progress indicator.
   - Lists all responding SSE/HTTP MCP endpoints and their exposed tools.
3. `[3] 📸 Baseline Picture & Security Drift Analysis`:
   - Submenu options:
     - `[a] 📸 Save Current State as Baseline Security Picture` (saves to `~/.mcp-vuln/state/security_picture.json`).
     - `[b] 🔍 Compare Current State Against Baseline Picture` (runs `SecurityPictureDiffer` and renders categorized drift report).
     - `[c] 🔙 Return to Main Menu`.
4. `[4] 🛡️  Vulnerability Audit, Fingerprinting & Remediation`:
   - Runs cryptographic tool signature checks (`TamperDetector`).
   - Deep probes unknown/unidentified servers via live stdio handshake.
   - Launches interactive multi-client config auto-patcher (`do_fix_multi_client`).
5. `[5] 📦 Export Reports & Compliance`:
   - Export options: SARIF report, CycloneDX 1.6 SBOM, raw JSON Security Picture, or Markdown executive summary.
6. `[0] 🚪 Exit`:
   - Restores terminal state and exits cleanly.

### 2.4 Terminal Safety, Alternate Buffer & Sanitization

1. Alternate Screen Buffer:
   - Enter alternate buffer: `\033[?1049h\033[?25l`
   - Show cursor on prompt: `\033[?25h`
   - Restore standard buffer on exit: `\033[?25h\033[?1049l`
2. Signal Traps:
   - Trap `SIGINT` (Ctrl+C) and `SIGTERM` using `signal.signal(signal.SIGINT, handle_sigint)`.
   - Always invoke `restore_terminal()` in `finally:` blocks.
3. Input Sanitization:
   - Apply `sanitize_ansi()` regex stripping on all user inputs to block ANSI escape injections.

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_113_1 (Zero-Arg TTY Invocation):** Running `mcp-vuln` with no arguments in an interactive terminal immediately renders the Command Hub header and menu.
- [ ] **INVARIANT_113_2 (Non-TTY Pipeline Safety):** Running `mcp-vuln` in a non-interactive shell without arguments prints standard CLI usage/help without hanging on `input()`.
- [ ] **INVARIANT_113_3 (Terminal Restoration Guarantee):** Exiting via option `0`, pressing Ctrl+C, or encountering an unhandled exception cleanly restores cursor visibility and exits the alternate buffer.
- [ ] **INVARIANT_113_4 (ANSI Injection Immunity):** Feeding malformed ANSI escape sequences into the menu prompt strips the sequences safely.
- [ ] **INVARIANT_113_5 (Submenu Navigation Fluidity):** Navigating into any submenu (such as the Drift Analysis submenu) allows returning to the main menu without terminating the hub.
- [ ] **INVARIANT_113_6 (Automated Test Suite):** `tests/test_interactive_hub.py` verifies status header generation, simulated stdin menu choices, non-TTY fallbacks, and signal handler restoration.

---

## 4. Deliverables

1. `src/mcp_vulnerabilities/audit/hub.py`: Upgraded Command Hub implementation with dynamic status header, 17-client telemetry, network scanner menu, baseline drift menu, and alternate buffer management.
2. `src/mcp_vulnerabilities/cli.py`: Integrated zero-argument TTY auto-dispatch and `mcp-vuln hub` subcommand.
3. `tests/test_interactive_hub.py`: Test suite simulating hub interactions and verifying terminal restoration and status header logic.

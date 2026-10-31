# Task 120: Wave 22 Verification & Documentation Sync (P1)

**Subsystem:** Quality Assurance, Verification & Documentation Sync (`tests/`, `README.md`, `CHANGELOG.md`, `docs/tasks/README.md`)  
**Priority:** `P1`  
**Parent Plan:** [master_plan_wave22_daemon_sandbox_tui_and_web_bridge.md](master_plan_wave22_daemon_sandbox_tui_and_web_bridge.md)

---

## 1. Objective & Problem Statement

Wave 22 introduces four significant, high-capability runtime systems to the `mcp-vulnerabilities` platform:
1. Continuous background monitoring daemon with OS and webhook alert dispatching (`mcp-vuln monitor`).
2. Pre-execution sandboxed network prober with honeytoken canary exfiltration detection (`mcp-vuln probe-safe`).
3. Zero-dependency interactive terminal split-pane TUI explorer (`mcp-vuln tui`).
4. Localhost loopback HTTP & WebSocket bridge linking the static web portal to live AI client configs (`mcp-vuln bridge`).

To maintain the rigorous engineering standards of the project, all new components must be verified against strict acceptance criteria, static type analysis, and comprehensive regression test suites. Furthermore, all public-facing documentation, command reference guides, changelogs, and the task board roadmap must be brought into complete synchronization.

This task formalizes the quality assurance, verification gates, and documentation deliverables for Wave 22.

---

## 2. Detailed Technical Requirements

### 2.1 Automated Test Suite Engineering (`tests/`)

1. **Daemon Monitoring Suite (`tests/daemon/test_monitor.py`)**:
   - Verify double-fork daemonization lifecycle, PID file locking, and process status checks (`--status`, `--stop`).
   - Mock asynchronous port scanner and client scanner to verify periodic monitoring cycle iterations.
   - Test alert debouncing: assert that identical drift findings do not trigger duplicate notifications within the 24-hour window.
   - Mock desktop notification systems (`osascript` on macOS, `notify-send` on Linux) to verify command formatting and non-blocking execution.
   - Mock Slack and Discord webhook endpoints to verify JSON payload structure, blocks, embed styling, and retry on failure.
2. **Sandbox Prober Suite (`tests/probe/test_sandbox_prober.py`)**:
   - Verify Docker argument construction: check `--read-only`, `--network none`, `--cap-drop ALL`, CPU and memory limits.
   - Verify restricted subprocess sandbox: assert complete scrubbing of host environment variables (`OPENAI_API_KEY`, `AWS_ACCESS_KEY_ID`, etc.) and injection of synthetic honeytokens.
   - Test canary exfiltration detector: simulate responses containing canary tokens and assert that `threat_level` transitions to `MALICIOUS` and `canary_leaked` is `True`.
   - Test timeout enforcement: simulate hanging server connections and verify clean subprocess termination within configured timeout.
3. **Split-Pane TUI Explorer Suite (`tests/audit/test_tui.py`)**:
   - Exercise `McpTuiExplorer` in headless test mode (`is_test=True`).
   - Test window partitioning: verify left pane (40%) and right pane (60%) dimension calculations.
   - Test keyboard navigation: verify `KEY_UP`, `KEY_DOWN`, `PAGE_UP`, `PAGE_DOWN`, and `TAB` window focus switching.
   - Test search filtering: simulate pressing `/` and query strings, verifying that filtered list matches expected server and tool names.
   - Test hotkey actions: simulate `f` (auto-fix), `c` (copy config), `p` (save picture), and verify action handlers.
   - Test dynamic terminal resize event (`curses.KEY_RESIZE`).
4. **Localhost Web Bridge Suite (`tests/daemon/test_bridge.py`)**:
   - Verify strict loopback interface binding (`127.0.0.1`).
   - Test CORS origin enforcement: assert that requests with origin `https://jmartynov.github.io` and `http://localhost:*` are accepted, while unauthorized external origins receive `403 Forbidden`.
   - Test session token challenge handshake and authentication header requirement.
   - Test `/health`, `/api/v1/scan`, `/api/v1/drift`, and `POST /api/v1/fix` endpoints with mock client configs.
   - Test WebSocket streaming during simulated scan cycles.
5. **Full Regression Validation**:
   - Ensure all existing 400+ pytest tests continue to pass with zero regressions:
     ```bash
     .venv/bin/pytest -q
     ```

### 2.2 Static Analysis & Quality Gates

1. **Formatting & Linting**:
   - Run `ruff check src/ tests/` ensuring zero warnings or lint errors.
   - Run `ruff format --check src/ tests/` ensuring formatting consistency.
2. **Strict Type Checking**:
   - Run `mypy --strict` across new daemon, probe, and audit modules:
     ```bash
     mypy --strict src/mcp_vulnerabilities/daemon/monitor.py \
                   src/mcp_vulnerabilities/daemon/bridge.py \
                   src/mcp_vulnerabilities/probe/sandbox_prober.py \
                   src/mcp_vulnerabilities/audit/tui.py
     ```

### 2.3 Documentation Synchronization

1. **`README.md` Updates**:
   - Document new CLI subcommands:
     - `mcp-vuln monitor --daemon [--interval 300] [--notify] [--webhook <url>]`
     - `mcp-vuln probe-safe --url <endpoint> [--sandbox-type docker|subprocess]`
     - `mcp-vuln tui`
     - `mcp-vuln bridge --port 8765`
   - Add ASCII / terminal mockups of the split-pane TUI explorer.
   - Add architecture diagram illustrating the interaction between the daemon, sandboxed prober, TUI, and web bridge.
2. **`CHANGELOG.md` Updates**:
   - Add entry for `v1.22.0`:
     - **Added**: Background port & network monitoring daemon (`mcp-vuln monitor`) with desktop & webhook alerts.
     - **Added**: Zero-trust pre-execution sandboxed prober (`mcp-vuln probe-safe`) with canary honeytoken exfiltration detection.
     - **Added**: Split-pane curses TUI explorer (`mcp-vuln tui`) with 1-touch hotkeys (`f`, `c`, `p`, `r`, `q`).
     - **Added**: Localhost Web Bridge daemon (`mcp-vuln bridge`) enabling 1-click in-browser live workstation auditing.
     - **Improved**: Full test suite expansion across all runtime components.
3. **`docs/tasks/README.md` Updates**:
   - Append Wave 22 section indexing Tasks 116 through 120 with statuses, file links, and verification summaries.

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_120_1 (Zero Test Regressions):** Existing baseline tests pass without failures or broken contracts.
- [ ] **INVARIANT_120_2 (Comprehensive Wave Coverage):** All four new subsystems (daemon, sandbox prober, TUI, web bridge) have dedicated unit and integration tests under `tests/daemon/`, `tests/probe/`, and `tests/audit/`.
- [ ] **INVARIANT_120_3 (Clean Static Analysis):** `ruff check` and `mypy --strict` pass with zero warnings across all newly authored files.
- [ ] **INVARIANT_120_4 (Documentation Parity):** `README.md`, `CHANGELOG.md`, and `docs/tasks/README.md` accurately document all new CLI commands, architecture, and task statuses.

---

## 4. Deliverables

1. `tests/daemon/test_monitor.py`: Daemon and notification test suite.
2. `tests/probe/test_sandbox_prober.py`: Sandbox driver, canary detection, and timeout test suite.
3. `tests/audit/test_tui.py`: Headless split-pane TUI explorer test suite.
4. `tests/daemon/test_bridge.py`: Localhost web bridge and CORS validation test suite.
5. `README.md`: Updated CLI command references, architectural diagrams, and feature descriptions.
6. `CHANGELOG.md`: Release notes for version 1.22.0.
7. `docs/tasks/README.md`: Wave 22 section linking Tasks 116–120.

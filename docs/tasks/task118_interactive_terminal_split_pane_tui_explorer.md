# Task 118: Interactive Terminal Split-Pane TUI Explorer (P0)

**Subsystem:** Interactive Terminal Experience (`src/mcp_vulnerabilities/audit/tui.py`, `src/mcp_vulnerabilities/cli.py`, `tests/audit/test_tui.py`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave22_daemon_sandbox_tui_and_web_bridge.md](master_plan_wave22_daemon_sandbox_tui_and_web_bridge.md)

---

## 1. Objective & Problem Statement

Developers and security engineers frequently manage complex workstation environments with multiple AI clients (Claude Desktop, Cursor, Zed, Windsurf, Cline, Goose, VS Code Copilot, Continue) and numerous local and network-accessible MCP servers.

Static CLI table outputs or lengthy JSON reports can be overwhelming to parse during active development or security triaging. Users require an interactive, visual, keyboard-driven terminal dashboard that matches the rich split-pane experience of modern developer tools like `lazygit`, `htop`, or `mcp-fingerprints`'s `tui.py`.

This task delivers **`mcp-vuln tui`**, an **Interactive Terminal Split-Pane TUI Explorer**:
1. Uses Python's standard `curses` library to deliver zero-external-dependency, high-speed split-pane terminal rendering across macOS, Linux, and Windows terminal emulators.
2. Displays a synchronized dual-pane layout:
   - **Left Pane (40% width)**: Scrollable list of all discovered local AI client servers and network MCP endpoints, color-coded with visual severity badges (`[CRIT]`, `[HIGH]`, `[MED]`, `[CLEAN]`).
   - **Right Pane (60% width)**: Comprehensive, real-time inspection view detailing CVE IDs, CVSS scores, affected version ranges, safe upgrade versions, tool parameter schemas, and dangerous AST sinks.
3. Provides one-touch interactive hotkeys:
   - `[f]` **Auto-Fix Config**: Automatically applies safe version upgrades to the client configuration file.
   - `[c]` **Copy Client Config**: Copies sanitized JSON configuration to the system clipboard (`pbcopy`, `xclip`, `clip`).
   - `[p]` **Save Security Picture**: Snapshots the current live picture to `~/.mcp-vuln/state/security_picture.json`.
   - `[r]` **Re-Probe / Refresh**: Re-runs local client discovery and network scanning asynchronously.
   - `[/]` **Interactive Search**: Filters servers by name, client, or vulnerability ID.
   - `[q]` **Quit**: Cleanly restores the terminal screen.
4. Seamlessly integrates into `mcp-vuln hub` as an interactive menu option or launches directly via `mcp-vuln tui`.

---

## 2. Detailed Technical Requirements

### 2.1 Curses Layout & Window Management (`src/mcp_vulnerabilities/audit/tui.py`)

1. **Terminal Window Architecture**:
   - Class `McpTuiExplorer`:
     - Initializes with `stdscr` and data models from `UniversalClientConfigScanner`, `NetworkScanner`, and `VulnerabilityMatcher`.
     - Layout partitioning:
       - **Header Window** (Height: 3 lines, Top: 0):
         - Title: `🛡️  MCP SECURITY EXPLORER v1.22.0  🛡️`
         - Subtitle: `OS: <platform> | Discovered: <N> Servers | Posture: <Status Badge> | Baseline: <Synced/Drift>`
       - **Left Window (Server List)** (Width: 40%, Top: 3, Height: `H - 5`):
         - Box bordered with scroll indicator (`▲ / ▼`).
         - Displays server items: `[CRIT] <client>:<server_name>` with cursor highlight on currently selected item.
       - **Right Window (Details Inspector)** (Width: 60%, Top: 3, Height: `H - 5`):
         - Box bordered with multi-section scrollable inspector:
           - Section A: Server Identity & Origin (Client, Path, Transport, Package, Version).
           - Section B: Known Vulnerabilities (CVE/GHSA ID, CVSS score, severity badge, safe version).
           - Section C: Capabilities & Tools (Tool names, descriptions, input schemas, reachability tags).
           - Section D: Baseline & Hash (Canonical SHA-256 hash, tamper status).
       - **Footer Window** (Height: 2 lines, Bottom: `H - 2`):
         - Hotkeys bar: `[f] Fix  [c] Copy  [p] Save Picture  [r] Re-probe  [/] Search  [q] Quit`
         - Status message timer (e.g. `✅ Config copied to clipboard!`).

2. **Color Palette & Visual Badges**:
   - Initialize standard curses color pairs:
     - Pair 1: Header/Highlight (White on Blue)
     - Pair 2: Selected Row (Black on White)
     - Pair 3: Clean Status (Green on Default)
     - Pair 4: Critical Severity (Red on Default)
     - Pair 5: High / Warning Severity (Yellow/Orange on Default)
     - Pair 6: Info / Path (Cyan on Default)
   - Graceful fallback for non-color terminals: renders ASCII indicators `[!CRIT!]`, `[*HIGH*]`, `[CLEAN]`.

3. **Dynamic Terminal Resizing**:
   - Traps `curses.KEY_RESIZE` events.
   - Recalculates pane dimensions dynamically without flickering or index out of bound exceptions.
   - Minimum terminal size check: requires at least 80x24 characters; displays `Terminal too small (need 80x24)` if screen is below threshold.

### 2.2 Navigation, Filtering & Interactive Hotkeys

1. **Keyboard Navigation**:
   - `KEY_UP` / `k`: Move selection up.
   - `KEY_DOWN` / `j`: Move selection down.
   - `KEY_PPAGE` / `PAGE_UP`: Page up by 10 items.
   - `KEY_NPAGE` / `PAGE_DOWN`: Page down by 10 items.
   - `TAB`: Toggle focus between Left pane (server list) and Right pane (tool inspector scrolling).
2. **Interactive Search & Filtering (`/`)**:
   - Pressing `/` opens an interactive input prompt in the footer.
   - Filters the displayed server list in real-time matching query against:
     - Server name
     - Client name (e.g. `cursor`, `claude`)
     - Tool names
     - CVE / GHSA identifiers
   - Pressing `ESC` or empty `ENTER` cancels search and restores full server inventory.
3. **Action Handlers**:
   - `[f]` **Auto-Fix**: Invokes `ClientConfigFixer.fix_config()` for the selected server's client file, updates version to safe target, reloads inventory, and displays confirmation in the status bar.
   - `[c]` **Copy Config**: Formats clean client JSON snippet (with secret tokens masked) and writes to clipboard via `copy_to_clipboard()` (`pbcopy` / `xclip` / `clip`).
   - `[p]` **Save Picture**: Calls `SecurityPicture.save()` to baseline storage and updates baseline status indicator to "Synced".
   - `[r]` **Re-Probe**: Triggers background network probe and client scan, updating state without exiting the TUI.
   - `[q]` / `KEY_ESC`: Exits TUI loop, releases curses window, restores terminal cursor and alternate screen buffer.

### 2.3 Headless / Test Simulation Mode

- Support a non-interactive test mode (`is_test=True`):
  - Allows unit tests to instantiate `McpTuiExplorer` without an active TTY.
  - Exposes `handle_keystroke(ch: int)` to simulate user interactions and verify state transitions in automated `pytest` suites.

### 2.4 CLI Subcommand & Hub Integration (`src/mcp_vulnerabilities/cli.py`)

- Subcommand:
  ```bash
  mcp-vuln tui [--target <localhost>] [--ports <spec>]
  ```
- Hub Menu Integration:
  - Option `[6] 🎛️ Launch Split-Pane TUI Explorer` inside `InteractiveTerminalHub` (`mcp_vulnerabilities/audit/hub.py`).

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_118_1 (Terminal State Restoration):** Exiting the TUI (via `q`, `SIGINT`, or error) strictly restores terminal cursor visibility, echo, and exits alternate buffer (`curses.endwin()`).
- [ ] **INVARIANT_118_2 (Dynamic Resize Stability):** Triggering `curses.KEY_RESIZE` while browsing dynamically resizes panes without raising unhandled curses exceptions or clipping content.
- [ ] **INVARIANT_118_3 (Safe Clipboard Export):** Pressing `c` copies valid JSON with sensitive tokens masked (`***REDACTED***`).
- [ ] **INVARIANT_118_4 (One-Touch Fix Integrity):** Pressing `f` on a vulnerable server modifies only the target client configuration file and immediately updates the server badge to `[CLEAN]`.
- [ ] **INVARIANT_118_5 (Zero-Dependency Curses):** TUI operates purely using standard library `curses` without requiring third-party libraries (`textual`, `rich`, `prompt_toolkit`).
- [ ] **INVARIANT_118_6 (Test Suite Coverage):** `tests/audit/test_tui.py` exercises server listing, detail rendering, navigation keys, filter matching, and action dispatch in headless test mode.

---

## 4. Deliverables

1. `src/mcp_vulnerabilities/audit/tui.py`: Full implementation of `McpTuiExplorer`, window partitioning, curses color handling, keyboard navigation, filtering, clipboard export, and auto-fix triggers.
2. `src/mcp_vulnerabilities/audit/hub.py`: Integration of TUI launcher into interactive command hub.
3. `src/mcp_vulnerabilities/cli.py`: Subcommand registration for `mcp-vuln tui`.
4. `tests/audit/test_tui.py`: Headless automated test suite verifying window layout, color pairs, key event dispatch, and clipboard helpers.

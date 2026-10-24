# Task 55: Multi-Client Auto-Fix Exporters & Interactive Security Hub (P0)

## 1. Architectural Context & Technical Objective

When security audits discover vulnerable MCP servers across multiple AI clients, fixing them manually by opening 9 different configuration files and hand-editing versions or arguments is tedious and error-prone. Furthermore, operators need an interactive, central command terminal to explore vulnerability timelines, inspect tool diffs, and approve security updates with a single keystroke.

`mcp-fingerprints` contains:
1. `config_exporter.py`: Automated configuration exporters supporting native schemas for Claude Desktop, Cursor, Zed, Cline, and Windsurf.
2. `hub.py`: A full-featured interactive terminal console with emoji menus, keyboard navigation, and side-by-side diff previews.

### Core Objectives:
1. **Multi-Client Config Auto-Fixer**:
   - Enhance `mcp-vuln fix` and `mcp-vuln resolve`:
     - Discover vulnerable servers across all 9 supported AI clients.
     - Compute the recommended safe target version using `VulnerabilityCorrelator`.
     - Automatically rewrite configuration files in their native format (JSON, YAML, Zed `context_servers`).
     - Create atomic timestamped backups (`<config>.bak.<timestamp>`) before modifying any file.
     - Support `--dry-run` to preview unified diffs before applying changes.
2. **Interactive Security Terminal Hub (`mcp-vuln hub`)**:
   - Provide an emoji-driven interactive terminal console:
     ```
     =======================================================
                🛡️  MCP SECURITY COMMAND HUB  🛡️
     =======================================================
     [1] 🔍 Universal Audit (Scan all 9 AI Clients + Global)
     [2] 🛡️  Supply-Chain Integrity Check (Verify Tool Signatures)
     [3] 📊 View Interactive CVE Vulnerability Timelines
     [4] ⚡ Unknown Server Fingerprint & Live Prober
     [5] 🔧 Multi-Client One-Click Config Auto-Patcher
     [6] 📦 Export Audited Configurations (SARIF / CycloneDX SBOM)
     [0] 🚪 Exit
     =======================================================
     ```
   - Connect all underlying CLI engines (audit, tamper detection, prober, auto-fix, SARIF export) into an integrated terminal experience.

---

## 2. Target Files & Documentation
- `src/mcp_vulnerabilities/audit/fixer.py`
- `src/mcp_vulnerabilities/audit/config_exporter.py`
- `src/mcp_vulnerabilities/hub.py` (New module)
- `src/mcp_vulnerabilities/cli.py`
- `tests/test_multiclient_autofix_and_hub.py`
- `docs/tasks/README.md`

---

## 3. Super Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Multi-Client In-Place Config Remediation Invariant
- **Preconditions**: Create vulnerable server entries across three distinct client configs:
  - Claude Desktop: `claude_desktop_config.json` with `@modelcontextprotocol/server-filesystem@0.6.0`.
  - Zed: `settings.json` with `context_servers` format.
  - Windsurf: `mcp_config.json`.
- **Test Steps**:
  1. Run `mcp-vuln fix --all-clients --write`.
- **Invariants**:
  - [x] **INVARIANT_1A (Version Pinning)**: The version in all three configs MUST be bumped to the minimum safe version (`>=0.6.2`).
  - [x] **INVARIANT_1B (Format Integrity)**: Zed's `context_servers` nested format and Windsurf's format MUST maintain exact valid syntax.
  - [x] **INVARIANT_1C (Preservation of Non-MCP Fields)**: Non-MCP configuration blocks (e.g. Zed font sizes, editor themes) MUST be preserved completely intact.
  - [x] **INVARIANT_1D (Atomic Backups)**: A `.bak.<timestamp>` file MUST exist for each modified configuration.

### Scenario 2: Dry-Run Diff Preview Invariant
- **Preconditions**: Same vulnerable configs as Scenario 1.
- **Test Steps**:
  1. Run `mcp-vuln fix --all-clients --dry-run`.
- **Invariants**:
  - [x] **INVARIANT_2A (No Write)**: Zero target config files or backup files are written to disk.
  - [x] **INVARIANT_2B (Unified Diff Output)**: Standard unified diffs (`--- a/config.json +++ b/config.json`) are rendered to stdout highlighting the version updates.

### Scenario 3: Non-Interactive / CI Headless Fallback Invariant
- **Preconditions**: Standard CI pipeline running with redirected or piped stdin (`isatty() == False`).
- **Test Steps**:
  1. Invoke `mcp-vuln hub`.
- **Invariants**:
  - [x] **INVARIANT_3A (No Freeze)**: The process MUST NOT block indefinitely waiting for TUI input.
  - [x] **INVARIANT_3B (Graceful Exit)**: Immediately exits with a descriptive error message: `"Interactive hub requires an interactive TTY terminal. Use headless CLI commands in CI/CD."`

### Scenario 4: Interactive Hub Menu Navigation Invariant
- **Preconditions**: Interactive TTY terminal session.
- **Test Steps**:
  1. Simulate keyboard inputs selecting `[1] Universal Audit` and `[0] Exit`.
- **Invariants**:
  - [x] **INVARIANT_4A**: Launches the universal audit engine and displays results cleanly.
  - [x] **INVARIANT_4B**: Returns to the main menu and terminates cleanly on option 0 without leaking ANSI escape sequences.

---

## 4. Implementation Steps

1. In `src/mcp_vulnerabilities/audit/fixer.py`:
   - Integrate `mcp_fingerprints.config_exporter` for Zed, Windsurf, Cline, VS Code, and Claude Desktop.
   - Implement multi-client atomic file updater with backup logic.
2. Create `src/mcp_vulnerabilities/hub.py`:
   - Implement `McpSecurityHub` with interactive text menus and sub-command routing.
3. In `src/mcp_vulnerabilities/cli.py`:
   - Add `mcp-vuln hub` subcommand.
   - Enhance `mcp-vuln fix` with `--all-clients`, `--client`, and `--dry-run` flags.
4. Author comprehensive test suite in `tests/test_multiclient_autofix_and_hub.py`.
5. Verify `pytest -q tests/test_multiclient_autofix_and_hub.py` passes 100%.

## Non-Interactive Completion Directive
Execute this task end-to-end without asking interactive questions. Implement `src/mcp_vulnerabilities/hub.py`, enhance `src/mcp_vulnerabilities/audit/fixer.py` and `src/mcp_vulnerabilities/cli.py`. Author the comprehensive test suite in `tests/test_multiclient_autofix_and_hub.py`, verify that all tests pass (`pytest -q`), and conclude directly with a complete patch so the remote environment cleanly transitions to `Completed`.

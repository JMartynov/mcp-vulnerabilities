# Task 138: Full 17-Client Automated Mock Acceptance Test Suite (P1)

**Subsystem:** Universal Client Auditing & Acceptance Testing (`src/mcp_vulnerabilities/audit/parsers.py`, `tests/acceptance/test_17_clients.py`)  
**Priority:** `P1`  
**Parent Plan:** [master_plan_wave24_empirical_remediation_and_feature_hardening.md](master_plan_wave24_empirical_remediation_and_feature_hardening.md)

---

## 1. Objective & Problem Statement

The platform's client auditing engine (`src/mcp_vulnerabilities/audit/parsers.py`) supports 17 universal AI clients through the `UniversalClientConfigScanner` class:
1. `claude_desktop`
2. `claude_code`
3. `cursor`
4. `windsurf`
5. `zed`
6. `cline`
7. `roo_code`
8. `goose`
9. `continue`
10. `jetbrains_junie`
11. `vscode`
12. `antigravity`
13. `openhands`
14. `trae`
15. `lm_studio`
16. `librechat`
17. `openwebui`

However, while earlier test suites (`tests/test_universal_9client_audit.py`) verified the initial 9 clients, the remaining 8 clients lacked comprehensive end-to-end acceptance tests. Each AI client employs its own filesystem layout, configuration schema, transport configuration, and variable expansion conventions. Without an automated mock acceptance test suite exercising all 17 clients simultaneously:
- Regressions in configuration path resolvers or schema parsers can go unnoticed.
- Sensitive environment variables (e.g. `API_KEY`, `DATABASE_PASSWORD`, auth tokens) might leak without proper redaction.
- Non-standard JSON formats (such as trailing commas, comments, or JSON5 in IDE configs) can cause runtime parse failures.

This task creates a comprehensive, automated end-to-end acceptance test suite in `tests/acceptance/test_17_clients.py` that populates a synthetic filesystem hierarchy for all 17 clients, validates parsing and transport detection, and asserts strict credential redaction invariants.

---

## 2. Detailed Technical Requirements

### 2.1 Supported 17-Client Mock Tree Matrix

`tests/acceptance/test_17_clients.py` must synthesize and validate mock configuration files for each of the 17 clients:

| # | Client Name | Default Configuration File Path (relative to `$HOME`) | Schema Structure & Transport |
| :-: | :--- | :--- | :--- |
| **1** | **Claude Desktop** | `Library/Application Support/Claude/claude_desktop_config.json` | `{"mcpServers": {"name": {"command": "...", "args": [...]}}}` |
| **2** | **Claude Code** | `.claude.json` / `.claude/config.json` | `{"mcpServers": {"name": {"command": "...", "args": [...]}}}` |
| **3** | **Cursor** | `.cursor/mcp.json` | `{"mcpServers": {"name": {"command": "...", "args": [...]}}}` |
| **4** | **Windsurf** | `.codeium/windsurf/mcp_config.json` | `{"mcpServers": {"name": {"command": "...", "args": [...]}}}` |
| **5** | **Zed** | `.config/zed/settings.json` | `{"context_servers": {"name": {"command": "...", "args": [...]}}}` |
| **6** | **Cline** | `Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `{"mcpServers": {"name": {"command": "...", "args": [...]}}}` |
| **7** | **Roo Code** | `Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json` | `{"mcpServers": {"name": {"command": "...", "args": [...]}}}` |
| **8** | **Goose** | `.config/goose/config.yaml` | `extensions:\n  name:\n    cmd: ...\n    args: [...]` |
| **9** | **Continue** | `.continue/config.json` | `{"experimental": {"modelContextProtocolServers": [{"name": "...", "transport": {...}}]}}` |
| **10** | **JetBrains Junie** | `Library/Application Support/JetBrains/Junie/mcp.json` | `{"servers": [{"name": "...", "command": "..."}]}` |
| **11** | **VS Code** | `.vscode/mcp.json` / `.config/Code/User/settings.json` | `{"mcpServers": {"name": {"command": "...", "args": [...]}}}` |
| **12** | **Antigravity** | `.gemini/antigravity/mcp_config.json` | `{"mcpServers": {"name": {"command": "...", "args": [...]}}}` |
| **13** | **OpenHands** | `.openhands/mcp.json` / `.openhands/config.toml` | `{"mcp": {"servers": {"name": {"command": "..."}}}}` |
| **14** | **Trae** | `.trae/mcp.json` | `{"mcpServers": {"name": {"command": "...", "args": [...]}}}` |
| **15** | **LM Studio** | `.cache/lm-studio/mcp/config.json` | `{"mcpServers": {"name": {"command": "...", "args": [...]}}}` |
| **16** | **LibreChat** | `librechat.yaml` | `mcpServers:\n  name:\n    type: stdio\n    command: ...` |
| **17** | **OpenWebUI** | `openwebui_mcp.json` | `{"mcp_servers": [{"name": "...", "url": "http://127.0.0.1:8000/sse"}]}` |

### 2.2 Acceptance Test Suite Architecture (`tests/acceptance/test_17_clients.py`)

1. **`build_synthetic_17_client_tree(tmp_path: Path) -> Path`**:
   - Creates the complete directory structure and writes syntactically valid (and realistic) configuration files for all 17 clients under a single temporary root directory.
   - Configures a variety of transports:
     - `stdio` processes: `npx`, `uvx`, `python`, `node`.
     - `sse` endpoints: `http://localhost:8000/sse`.
     - `streamable-http` endpoints: `http://localhost:8080/mcp`.
   - Injects credentials into `env` dictionaries:
     - `OPENAI_API_KEY="sk-live-supersecret12345"`
     - `GITHUB_PERSONAL_ACCESS_TOKEN="ghp_supersecret67890"`
     - `DATABASE_URL="postgres://admin:topsecretpw@localhost/db"`
2. **Test Cases**:
   - `test_individual_client_discovery`: Iterates over each of the 17 clients independently, asserting that `UniversalClientConfigScanner` finds and parses its respective configuration.
   - `test_unified_17_client_scan`: Runs `scanner.scan_all_clients()` against the entire synthetic tree, asserting that all 17 clients and their servers are extracted in a single pass.
   - `test_secret_token_redaction_invariant`: Asserts that zero raw secret tokens are present in any returned `DiscoveredClientServer.env` or arguments. All credentials must be masked as `***REDACTED***`.
   - `test_relaxed_json_syntax_resilience`: Injects comments (`//`, `/* */`), trailing commas, and unquoted keys into client configs and verifies parsing succeeds without throwing `json.JSONDecodeError`.
   - `test_missing_and_corrupt_files`: Asserts that missing files or non-JSON garbage files are skipped with a warning log rather than an uncaught exception.

---

## 3. Invariant Requirements & Verification Plan

### 3.1 Acceptance Invariants
1. **100% Discovery Parity**:
   - `len(results.keys()) >= 17` when all 17 client configuration files are present in the mock root.
2. **Zero Credential Leakage**:
   - `assert "supersecret" not in json.dumps([asdict(s) for s in all_servers])`.
3. **Transport Accuracy**:
   - Stdio commands must populate `command` and `args`.
   - SSE and HTTP endpoints must populate `url` and set `transport` accordingly (`"sse"` or `"streamable-http"`).
4. **Crash Immunity**:
   - Corrupted or unreadable configurations for one client must never abort discovery for the remaining 16 clients.

---

## 4. Deliverables & Integration Checklist

- [ ] Create `tests/acceptance/` directory if not present.
- [ ] Author `tests/acceptance/test_17_clients.py` with mock tree generator and comprehensive test cases.
- [ ] Verify relaxed JSON parsing and secret masking across all 17 clients.
- [ ] Run `pytest tests/acceptance/test_17_clients.py` and achieve 100% green pass rate.

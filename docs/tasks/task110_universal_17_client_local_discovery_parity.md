# Task 110: Universal 17-Client Local Discovery Parity (P0)

**Subsystem:** Local Client Discovery Engine (`src/mcp_vulnerabilities/audit/parsers.py`, `tests/test_17_client_discovery.py`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave21_network_inspection_security_picture_and_cli_hub.md](master_plan_wave21_network_inspection_security_picture_and_cli_hub.md)

---

## 1. Objective & Problem Statement

In developer workstations, AI assistant configurations are distributed across numerous applications, IDEs, and CLI tools. Currently, `UniversalClientConfigScanner` in `src/mcp_vulnerabilities/audit/parsers.py` supports only 9 client formats. Modern development teams leverage a much broader spectrum of 17 AI tools, ranging from IDE extensions (Cursor, Windsurf, JetBrains Junie, Roo Code, Trae) to autonomous agent frameworks (Goose, OpenHands, Claude Code CLI, Antigravity) and local LLM runners (LM Studio, LibreChat, OpenWebUI).

Furthermore, configuration files often employ non-standard extensions:
- JSON with Comments (JSONC), which causes standard `json.loads()` to crash.
- Unexpanded environment variable interpolations (e.g., `${API_KEY}` or `$ANTHROPIC_API_KEY`).
- Cleartext secret tokens and bearer credentials embedded directly into `env` dictionaries, presenting an exfiltration hazard when auditing or exporting configuration pictures.

This task upgrades `UniversalClientConfigScanner` to full parity with the 17 AI clients supported in `mcp-fingerprints`, introduces robust lossless JSONC comment-stripping, handles YAML configs (for Goose and LibreChat), resolves environment variables, and enforces mandatory secret token redaction (`***REDACTED***`).

---

## 2. Detailed Technical Requirements

### 2.1 Complete 17-Client Configuration Matrix (`src/mcp_vulnerabilities/audit/parsers.py`)

Expand `UniversalClientConfigScanner.SUPPORTED_CLIENTS` to include all 17 clients:
```python
SUPPORTED_CLIENTS = (
    "claude",           # Claude Desktop
    "claude-code",      # Claude Code CLI (~/.claude.json & project root .mcp.json)
    "cursor",           # Cursor (~/.cursor/mcp.json & project .cursor/mcp.json)
    "windsurf",         # Windsurf (~/.codeium/windsurf/mcp_config.json)
    "zed",              # Zed Editor (~/.config/zed/settings.json)
    "cline",            # Cline VS Code Extension
    "roo-code",         # Roo Code VS Code Extension
    "goose",            # Goose Agent Framework (~/.config/goose/config.yaml)
    "continue",         # Continue.dev (~/.continue/config.json)
    "junie",            # JetBrains Junie (.idea/mcp.json & ~/.junie/mcp/)
    "vscode",           # VS Code / Copilot mcp.json & settings.json
    "antigravity",      # Antigravity (~/.gemini/config/mcp_config.json)
    "openhands",        # OpenHands Agent (~/.openhands/mcp.json)
    "trae",             # Trae IDE (~/.trae/mcp.json)
    "lmstudio",         # LM Studio (~/.lmstudio/mcp.json)
    "librechat",        # LibreChat (librechat.yaml)
    "openwebui",        # OpenWebUI (openwebui.json / ~/.openwebui/mcp.json)
)
```

### 2.2 Cross-Platform Path Resolution

Implement path discovery across macOS, Linux, and Windows for each client:
1. **Claude Desktop**:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
2. **Claude Code CLI**:
   - User home: `~/.claude.json`, `~/.claude/config.json`
   - Current working directory / project root: `.mcp.json`
3. **Cursor**:
   - User home: `~/.cursor/mcp.json`
   - Project directory: `.cursor/mcp.json`
4. **Windsurf**:
   - `~/.codeium/windsurf/mcp_config.json`
5. **Zed**:
   - `~/.config/zed/settings.json`, `~/Library/Application Support/Zed/settings.json`
6. **Cline**:
   - `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
   - Linux: `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
7. **Roo Code**:
   - `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json`
   - Linux: `~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json`
8. **Goose**:
   - `~/.config/goose/config.yaml`
9. **Continue.dev**:
   - `~/.continue/config.json`
10. **JetBrains Junie**:
    - Project root: `.idea/mcp.json`
    - User home: `~/.junie/mcp/config.json`
11. **VS Code / Copilot**:
    - `~/Library/Application Support/Code/User/globalStorage/github.copilot/mcp.json`
    - `~/.vscode/mcp.json`
12. **Antigravity**:
    - `~/.gemini/config/mcp_config.json`
13. **OpenHands**:
    - `~/.openhands/mcp.json`
14. **Trae**:
    - `~/.trae/mcp.json`
15. **LM Studio**:
    - `~/.lmstudio/mcp.json`
16. **LibreChat**:
    - `librechat.yaml`, `~/.config/librechat/librechat.yaml`
17. **OpenWebUI**:
    - `openwebui.json`, `~/.openwebui/mcp.json`
18. **Global npm & npx Cache Discovery**:
    - Query `npm root -g` to scan installed global MCP packages (`@modelcontextprotocol/server-*`, `*mcp*`).
    - Inspect npx cache directories (`~/.npm/_npx/`).

### 2.3 Lossless JSONC Parsing & YAML Support

1. Lossless JSONC Comment Removal:
   - Implement regex/state machine parser that strips:
     - Single line comments: `// ...`
     - Block comments: `/* ... */`
   - **Crucial Rule**: Never strip `//` when part of a string value (such as URL `http://` or `https://` or regex pattern).
2. YAML Parsing for Goose & LibreChat:
   - Use `yaml.safe_load()` when parsing `.yaml` or `.yml` files.

### 2.4 Environment Variable Expansion & Secret Redaction

1. Environment Variable Interpolation:
   - Expand `${VARIABLE_NAME}` and `$VARIABLE_NAME` in string arguments and environment values using `os.environ`.
   - If variable is undefined, preserve original token without crashing.
2. Mandatory Secret Redaction (`***REDACTED***`):
   - Define sensitive key regex pattern:
     ```python
     SENSITIVE_KEY_PATTERN = re.compile(
         r"(?i)(key|token|secret|password|auth|bearer|credential|api_key|access_token|private)"
     )
     ```
   - For all discovered server environment variables (`env`), if key matches `SENSITIVE_KEY_PATTERN` or value starts with `sk-`, `ghp_`, `xoxb-`, etc., replace the value with `"***REDACTED***"`.
   - In `command_args`, redact arguments following flags like `--api-key`, `--token`, `--secret`.

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_110_1 (Complete 17-Client Enumeration):** `UniversalClientConfigScanner.SUPPORTED_CLIENTS` contains all 17 specified client identifiers.
- [ ] **INVARIANT_110_2 (JSONC Resilience):** A configuration file with inline `// comment` and multi-line `/* comment */` surrounding URLs (`https://api.example.com`) parses accurately into a Python dictionary.
- [ ] **INVARIANT_110_3 (Secret Zero-Leakage Guarantee):** Server configurations containing `OPENAI_API_KEY`, `GITHUB_TOKEN`, or `--auth-token` always store `"***REDACTED***"` in memory and persisted output.
- [ ] **INVARIANT_110_4 (Project-Level Discovery):** Project-level configurations (`.mcp.json`, `.idea/mcp.json`, `.cursor/mcp.json`) are correctly recognized when scanning project directories.
- [ ] **INVARIANT_110_5 (YAML Parsing Reliability):** Goose `config.yaml` with nested extension configurations is cleanly translated to `DiscoveredClientServer` records.
- [ ] **INVARIANT_110_6 (Automated Test Suite):** `tests/test_17_client_discovery.py` exercises mock configuration fixtures for all 17 clients, JSONC comment removal, and secret redaction.

---

## 4. Deliverables

1. `src/mcp_vulnerabilities/audit/parsers.py`: Extended `UniversalClientConfigScanner` supporting all 17 clients, JSONC comment-stripping, YAML parsing, environment expansion, and credential redaction.
2. `tests/test_17_client_discovery.py`: Complete test suite with synthetic fixtures for all 17 AI clients and secret redaction validations.

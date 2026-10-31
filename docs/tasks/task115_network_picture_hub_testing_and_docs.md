# Task 115: Network, Picture & Hub Testing Suite and Documentation Sync (P1)

**Subsystem:** Quality Assurance, Integration Testing & Documentation (`README.md`, `tests/`)  
**Priority:** `P1`  
**Parent Plan:** [master_plan_wave21_network_inspection_security_picture_and_cli_hub.md](master_plan_wave21_network_inspection_security_picture_and_cli_hub.md)

---

## 1. Objective & Problem Statement

To deliver enterprise-grade reliability, the capabilities introduced across Wave 21 (network scanning, 17-client discovery parity, stateful security pictures, comparative drift analysis, and the interactive terminal hub) require end-to-end automated testing and comprehensive documentation.

This task delivers:
1. Four dedicated automated test suites (`tests/test_network_scanner.py`, `tests/test_17_client_discovery.py`, `tests/test_security_picture_diff.py`, `tests/test_interactive_hub.py`) ensuring zero regressions across all existing features while achieving 100% green test passes.
2. A comprehensive documentation refresh of `README.md` showcasing the Interactive Command Hub, Network & Port MCP Scanner, Stateful Security Picture & Drift Tracking workflow, and an expanded 17-Client Discovery Matrix.

---

## 2. Detailed Technical Requirements

### 2.1 Automated Test Suites Architecture

1. **`tests/test_network_scanner.py`**:
   - Uses `aiohttp.test_utils` or lightweight `asyncio` server fixtures:
     - Tests socket pre-check with immediate accept, filtered/dropped connection (timeout assertions), and closed ports.
     - Tests HTTP JSON-RPC 2.0 `initialize` probe and response handling.
     - Tests SSE event stream parsing and negotiated endpoint POST requests.
     - Tests CIDR subnet expansion with boundary limits (`max_hosts`).
     - Tests non-MCP HTTP responses (returns 404 or plain HTML) to ensure graceful handling without crashes.
2. **`tests/test_17_client_discovery.py`**:
   - Uses temporary directory fixtures (`tmp_path`) mocking standard config paths for all 17 supported clients:
     - Claude Desktop, Claude Code CLI (`.claude.json` and project root `.mcp.json`), Cursor, Windsurf, Zed, Cline, Roo Code, Goose (`config.yaml`), Continue.dev, JetBrains Junie (`.idea/mcp.json`), VS Code / Copilot, Antigravity, OpenHands, Trae, LM Studio, LibreChat, OpenWebUI.
   - Tests JSONC comment-stripping with embedded single-line (`//`), multi-line (`/* */`), and protected URLs (`http://`, `https://`).
   - Tests environment variable resolution and secret token redaction (`***REDACTED***`).
3. **`tests/test_security_picture_diff.py`**:
   - Tests `SecurityPicture` dataclass round-trip serialization and deserialization.
   - Tests differential analysis across all 6 explicit security categories:
     - 🚨 Newly introduced CVEs/GHSAs.
     - ✅ Resolved vulnerabilities.
     - ⚠️ Tamper incidents (hash mutations).
     - 🛡️ New high-risk tools (`shell_exec`, `write_file`).
     - 👥 Added shadow servers (local and network).
     - 🔄 Tool schema modifications.
   - Tests cumulative drift severity rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `CLEAN`).
4. **`tests/test_interactive_hub.py`**:
   - Tests `get_dynamic_status_header()` output formatting and data accuracy.
   - Mocks `sys.stdin` and `sys.stdout` to simulate user navigation through main menus and submenus.
   - Tests non-interactive TTY detection fallback.
   - Tests signal handling and terminal restoration.

### 2.2 Documentation Updates (`README.md`)

Update `README.md` with:
1. **Interactive Command Hub Showcase**:
   - Screenshot / ASCII diagram of the dynamic status header and interactive menu.
   - Quick start guide: `mcp-vuln` (zero args in TTY) or `mcp-vuln hub`.
2. **Network & Port MCP Scanner Guide**:
   - Examples for scanning localhost, custom ports, and CIDR subnets:
     ```bash
     # Scan default MCP ports on localhost
     mcp-vuln network-scan

     # Scan custom port range across a subnet
     mcp-vuln network-scan --cidr 192.168.1.0/24 --ports 3000-3010
     ```
3. **Stateful Security Picture & Drift Tracking Guide**:
   - CI/CD workflow examples for baseline capture and PR drift enforcement:
     ```bash
     # Save baseline state
     mcp-vuln audit --save-picture .mcp-baseline.json

     # Compare in CI pipeline and block on drift
     mcp-vuln audit --compare-picture .mcp-baseline.json --fail-on-drift
     ```
4. **Expanded 17-Client Discovery Matrix**:
   - Table detailing: Client Name, Configuration Path, Format (JSON / JSONC / YAML), Secret Redaction Support.

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_115_1 (Zero Test Regressions):** All pre-existing test suites (370+ tests) continue to pass green alongside new test modules.
- [ ] **INVARIANT_115_2 (Isolated Mock Fixtures):** No network tests bind to public interfaces or perform live external network requests.
- [ ] **INVARIANT_115_3 (Cross-Platform Path Compatibility):** Client discovery tests execute cleanly across macOS, Linux, and Windows file paths.
- [ ] **INVARIANT_115_4 (Documentation Truth & Sync):** Every CLI argument documented in `README.md` corresponds directly to functional arguments in `src/mcp_vulnerabilities/cli.py`.
- [ ] **INVARIANT_115_5 (Clean Linting & Typing):** `ruff check` and `mypy` pass across all new test files and documentation-referenced code.

---

## 4. Deliverables

1. `tests/test_network_scanner.py`: Full test suite for the network scanner engine.
2. `tests/test_17_client_discovery.py`: Full test suite for 17-client discovery, JSONC parsing, and secret sanitization.
3. `tests/test_security_picture_diff.py`: Full test suite for security picture serialization and differential drift analysis.
4. `tests/test_interactive_hub.py`: Full test suite for interactive terminal hub navigation and safety.
5. `README.md`: Updated comprehensive documentation covering Wave 21 capabilities.

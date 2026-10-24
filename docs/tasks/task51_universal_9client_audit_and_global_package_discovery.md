# Task 51: Universal 9-Client Audit & Global Package Discovery (P0)

## 1. Architectural Context & Technical Objective

Currently, `mcp-vuln audit` (and `audit-config`) only inspects Claude Desktop (`claude_desktop_config.json`), project `.claude.json`, and simple Cursor configs (`.cursor/mcp.json`). Developers using other AI editors or clients (VS Code Roo, Zed, Cline, Windsurf, Continue, LibreChat, OpenWebUI) or running globally installed npm MCP servers remain completely unprotected by automated audits.

`mcp-fingerprints` introduced `ConfigScanner` and `NpmGlobalScanner`, capable of discovering and extracting server configurations across **9 AI clients** and scanning global package prefixes.

### Core Objectives:
1. Integrate `mcp_fingerprints.ConfigScanner` and `NpmGlobalScanner` into `src/mcp_vulnerabilities/audit/parsers.py` and `src/mcp_vulnerabilities/cli.py`.
2. Expand `mcp-vuln audit` to support:
   - `--all-clients`: Automatically scans all standard config paths for all 9 supported AI clients.
   - `--client <name>`: Scans a specific client (`claude`, `cursor`, `vscode`, `zed`, `cline`, `windsurf`, `continue`, `librechat`, `openwebui`).
   - `--global`: Scans globally installed MCP packages in `npm root -g` and `npx` cache.
   - `--custom-config <path>`: Scans an arbitrary config file (JSON or YAML).
3. Correlate every discovered server and version against the OSV vulnerability database.
4. Output structured multi-client audit reports in Console (colored tables), JSON, and SARIF v2.1.0 (with accurate file path URIs).

---

## 2. Target Files & Documentation
- `src/mcp_vulnerabilities/audit/parsers.py`
- `src/mcp_vulnerabilities/audit/matcher.py`
- `src/mcp_vulnerabilities/audit/reporters.py`
- `src/mcp_vulnerabilities/cli.py`
- `tests/test_universal_9client_audit.py`
- `docs/tasks/README.md`

---

## 3. Super Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Universal 9-Client Parsing Invariant
- **Preconditions**: Create synthetic test fixtures representing valid config files for all 9 clients:
  1. Claude Desktop (`claude_desktop_config.json`)
  2. Claude Code (`.claude.json`)
  3. Cursor (`.cursor/mcp.json`)
  4. VS Code (`settings.json` with Roo/Continue MCP blocks)
  5. Zed (`settings.json` with `context_servers` format)
  6. Cline (`cline_mcp_settings.json`)
  7. Windsurf (`mcp_config.json`)
  8. LibreChat (`librechat.yaml`)
  9. OpenWebUI (`config.json`)
- **Test Steps**:
  1. Run `mcp-vuln audit --all-clients --config-root <test_fixtures_dir>`.
- **Invariants**:
  - [x] **INVARIANT_1A (Complete Extraction)**: Every server declared in each of the 9 configurations MUST be extracted with its `server_name`, `command`, `args`, `env`, and `source_client` accurately populated.
  - [x] **INVARIANT_1B (Format Robustness)**: JSON with comments (JSONC), trailing commas (Zed/VS Code), and YAML structures (LibreChat) MUST be parsed without throwing syntax errors.
  - [x] **INVARIANT_1C (Path Tracking)**: The resulting audit report MUST associate each finding with its exact source config file path.

### Scenario 2: Global Package Discovery Invariant (`--global`)
- **Preconditions**: Simulate global npm root and npx cache directories containing both secure and vulnerable MCP packages (e.g. `@modelcontextprotocol/server-filesystem@0.6.0`).
- **Test Steps**:
  1. Run `mcp-vuln audit --global`.
- **Invariants**:
  - [x] **INVARIANT_2A (Global Extraction)**: Globally installed `@modelcontextprotocol/*` and `*-mcp` packages MUST be identified.
  - [x] **INVARIANT_2B (Version Attribution)**: Package versions extracted from global `package.json` files MUST be matched against OSV advisories.
  - [x] **INVARIANT_2C (Source Labeling)**: Findings from global discovery MUST be clearly labeled as `Source: Global npm` or `Source: npx cache`.

### Scenario 3: Malformed Config Fault Tolerance Invariant
- **Preconditions**: Provide a corrupted JSON file (invalid syntax) in one client's config location, alongside valid configs for other clients.
- **Test Steps**:
  1. Run `mcp-vuln audit --all-clients`.
- **Invariants**:
  - [x] **INVARIANT_3A (Graceful Degradation)**: The scanner MUST log a non-fatal warning for the corrupted file and MUST NOT crash.
  - [x] **INVARIANT_3B (Continued Execution)**: All valid client configurations MUST still be fully audited and reported.

### Scenario 4: SARIF Schema Conformance Invariant
- **Preconditions**: Vulnerabilities found across multiple clients.
- **Test Steps**:
  1. Run `mcp-vuln audit --all-clients --format sarif --output audit.sarif`.
- **Invariants**:
  - [x] **INVARIANT_4A (SARIF 2.1.0)**: The generated SARIF file MUST validate against OASIS SARIF v2.1.0 schema.
  - [x] **INVARIANT_4B (Artifact Location)**: `result.locations[0].physicalLocation.artifactLocation.uri` MUST link to the specific client's configuration file (e.g. `file:///Users/.../.cursor/mcp.json`).

---

## 4. Implementation Steps

1. In `src/mcp_vulnerabilities/audit/parsers.py`:
   - Import `ConfigScanner` and `NpmGlobalScanner` from `mcp_fingerprints.config_scanner`.
   - Implement `UniversalClientConfigScanner` unifying 9-client discovery with existing `DiscoveredClientServer` data structures.
2. In `src/mcp_vulnerabilities/cli.py`:
   - Add `--all-clients`, `--client`, `--global`, and `--custom-config` flags to `audit` subparser.
3. In `src/mcp_vulnerabilities/audit/reporters.py`:
   - Update terminal table reporter, JSON formatter, and SARIF exporter to group and display results by client.
4. Author test suite in `tests/test_universal_9client_audit.py` with mock client environments.
5. Verify `pytest -q tests/test_universal_9client_audit.py` passes 100%.

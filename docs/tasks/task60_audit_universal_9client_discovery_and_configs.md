# Task 60: Empirical Audit — Universal 9-Client Discovery & Multi-Config Edge Cases (P0)

## 1. Architectural Context & Technical Objective

AI client configuration auditing (`audit/parsers.py`, `audit/config_exporter.py`) was expanded in Wave 10 to support 9 major clients (Claude Desktop, Cursor, Zed, Windsurf, Cline, VS Code Roo/Continue, Continue, LibreChat, OpenWebUI) and global packages. In production, developers use unconventional syntax: JSON with trailing commas, JSONC inline comments (`//`, `/* */`), environment variable substitution (`${HOME}/...`), multi-workspace VS Code overrides, circular directory symlinks in `.npx` caches, and Windows/POSIX mixed path separators.

This task conducts an autonomous, live empirical audit of all 9 client parsers and global package discovery across live edge-case config fixtures, verifies invariant integrity, authors `tests/audit/test_audit_task60.py`, and publishes a comprehensive technical report to `docs/audit/audit_task60_universal_9client_audit.md` grading all findings by **HIGH**, **MEDIUM**, and **LOW** severity.

---

## 2. Target Files & Isolation Boundaries
- Scope: `src/mcp_vulnerabilities/audit/parsers.py`, `src/mcp_vulnerabilities/audit/config_exporter.py`
- Test Suite: `tests/audit/test_audit_task60.py`
- Audit Deliverable: `docs/audit/audit_task60_universal_9client_audit.md`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Malformed & Permissive Configuration Parsing Invariant
- **Preconditions**: Create live configuration files with JSONC comments, single-line trailing commas, unquoted keys, and UTF-8 BOM headers across Claude, Cursor, and Zed.
- **Invariants**:
  - [x] **INVARIANT_1A (Non-Crashing Permissiveness)**: Permissive JSON/JSONC configs must parse successfully without throwing `json.decoder.JSONDecodeError`.
  - [x] **INVARIANT_1B (Semantic Integrity)**: Server arguments, environment dictionaries, and command flags must be extracted with 100% fidelity matching native client runtime behavior.

### Scenario 2: Global Package Discovery & Symlink Loop Guard Invariant
- **Preconditions**: Simulate global `npm -g` root and `.npx` cache containing circular directory symlinks and non-standard package structures.
- **Invariants**:
  - [x] **INVARIANT_2A (Symlink Cycle Immunity)**: The scanner must detect circular filesystem paths and terminate traversal without infinite loops or `RecursionError`.
  - [x] **INVARIANT_2B (Scoped vs Unscoped Disambiguation)**: Packages under `@scope/name` must be resolved with exact package names and ecosystems distinct from root modules.

### Scenario 3: Cross-Platform Path & Environment Variable Expansion Invariant
- **Preconditions**: Audit configurations containing mixed Windows backslashes (`\`) and POSIX forward slashes (`/`), plus `${VAR}` and `$VAR` environment references.
- **Invariants**:
  - [x] **INVARIANT_3A (Path Normalization)**: Executable paths (`node.exe`, `python`, `npx`) and command lines must normalize consistently across macOS, Linux, and Windows.
  - [x] **INVARIANT_3B (Environment Secret Redaction)**: Secret keys (e.g. `API_KEY`, `AUTH_TOKEN`) in audited output must be redacted and never leaked into plain-text stdout or unmasked SARIF logs.

---

## 4. Implementation Steps

1. Author live empirical test suite in `tests/audit/test_audit_task60.py` verifying all 3 scenarios and invariants.
2. Run live verification across the parser and config exporter codebase; fix any edge-case failures.
3. Author comprehensive technical report in `docs/audit/audit_task60_universal_9client_audit.md` detailing all evaluated invariants, findings graded by HIGH/MEDIUM/LOW, and concrete patch proposals.

## Non-Interactive Completion Directive
Execute this task end-to-end without asking interactive questions. Implement `tests/audit/test_audit_task60.py`, verify that all tests pass (`pytest -q`), generate the complete technical report in `docs/audit/audit_task60_universal_9client_audit.md`, and conclude directly with a complete patch so the remote environment cleanly transitions to `Completed`.

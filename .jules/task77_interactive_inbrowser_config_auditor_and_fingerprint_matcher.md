# Task 77: Interactive In-Browser Config Auditor & Fingerprint Matcher Dropzone (P1)

## 1. Architectural Context & Technical Objective

Currently, security auditing of local MCP setups requires cloning the repository and running the CLI (`mcp-vuln audit` or `mcp-vuln hub`). However, web portal visitors on [index.html](https://jmartynov.github.io/mcp-vulnerabilities/) often want an immediate, zero-install way to check whether their Claude Desktop, Cline, or Cursor setup is vulnerable.

The browser already loads `mcp_catalog_index.json` and can load individual shards on demand. By leveraging the canonical matching logic from `mcp_fingerprints.matcher`, we can provide a completely client-side, zero-telemetry **"Audit My MCP Setup"** dropzone / paste widget directly on `docs/index.html`.

This task creates an interactive in-browser configuration auditor that parses client JSON configs, matches installed packages against known CVEs and canonical fingerprints, and generates an instant visual security posture report with one-click copyable remediation diffs.

---

## 2. Target Files & Isolation Boundaries
- Scope: `docs/index.html`, `docs/app.js`, `docs/style.css`
- Deliverable: Client-side drag-and-drop / paste audit widget on `index.html` with instant vulnerability matching and copyable remediation patches.

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Multi-Client Config Ingestion & Parsing
- **Preconditions**: User drags, uploads, or pastes a config file in `#config-audit-zone`.
- **Invariants**:
  - [x] **INVARIANT_1A (Multi-Client Compatibility)**: Safely parse `claude_desktop_config.json`, `cline_mcp_settings.json`, and `cursor_config.json`.
  - [x] **INVARIANT_1B (Privacy & Zero-Telemetry)**: Execute 100% of parsing and matching within browser memory without sending user configs to any external server.

### Scenario 2: Catalog & Fingerprint Matching
- **Preconditions**: Parsed server command lines (e.g. `npx -y @modelcontextprotocol/server-filesystem`, `uvx neo4j-mcp`).
- **Invariants**:
  - [x] **INVARIANT_2A (Package Extraction)**: Extract ecosystem, package name, and pinned version from `command` and `args`.
  - [x] **INVARIANT_2B (Posture Report)**: Compare extracted packages against `catalogIndex` and display an instant audit summary:
    - Number of audited servers
    - Number of clean servers
    - Number of vulnerable servers with CVE IDs, CVSS scores, and recommended safe versions.

### Scenario 3: Remediation Diff & One-Click Copy
- **Preconditions**: At least one vulnerable server detected in user config.
- **Invariants**:
  - [x] **INVARIANT_3A (Patch Generation)**: Generate a JSON configuration diff showing the updated version pins (e.g. `@modelcontextprotocol/server-filesystem@0.6.0`).
  - [x] **INVARIANT_3B (Copy Action)**: Provide a one-click "Copy Remediated Config" button with visual feedback.

---

---

## 4. Execution Directives & Non-Interactive Completion
- **Non-Interactive Completion Directive**: Implement the required changes directly, ensure all acceptance criteria and invariants are satisfied, run relevant local tests to confirm pass, and finalize directly without asking open-ended questions so the remote VM cleanly transitions to Completed.
- **Heavy Dataset Guard**: Do NOT execute full dataset compilation or multi-megabyte builds (passports.json.gz). Use test mocks/fixtures.
- **Documentation Parity**: Keep comments, type annotations, and docstrings intact.

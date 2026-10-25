# Task 87: v1.2.0 Documentation & Specification Synchronization (P1)

**Target Wave:** Wave 17A (Documentation & Specification Sync)  
**Priority:** `P1` (Mandatory Release Documentation Gate)  
**Master Plan:** [`docs/tasks/IMPLEMENTATION_PLAN_WAVE17_CODE_REVIEW_DOCS_AND_RELEASE_V120.md`](IMPLEMENTATION_PLAN_WAVE17_CODE_REVIEW_DOCS_AND_RELEASE_V120.md)

---

## 1. Architectural Context & Technical Objective

Waves 15 and 16 introduced major new capabilities and architectural enhancements across the `mcp-vulnerabilities` platform:
1. **Inline MCP Reverse Proxy Interceptor (`mcp-vuln proxy`, Task 84)**:
   - New package `src/mcp_vulnerabilities/proxy/` (`ProxyPolicyEngine`, `PolicyDecision`, `McpStdioProxy`).
   - Intercepts bidirectional `stdio` JSON-RPC 2.0 traffic between MCP hosts (Claude Desktop, Cursor, Windsurf, Cline) and child MCP server processes.
   - Blocks `tools/call` requests targeting OSV `vulnerable_tools` or matching prompt-injection/command-injection patterns with JSON-RPC error code `-32001` (`MCP Security Policy Violation`), filters shadow/vulnerable tools from `tools/list`, redacts leaked credentials in responses, and writes structured JSONL telemetry (`--audit-log`).
2. **AST Interprocedural Call-Graph Reachability Engine (Task 85)**:
   - New package `src/mcp_vulnerabilities/analyzers/reachability/` (`AstReachabilityAnalyzer`, `DependencyReachability`, `ReachabilityReport`).
   - Traces multi-hop call graphs from `@mcp.tool()` / `server.tool()` entrypoints in Python (`.py`) and JS/TS (`.js`/`.ts`) MCP server source directories to third-party package imports and symbol calls (`REACHABLE_FROM_TOOL`, `IMPORTED_ONLY`, `UNREACHABLE`).
   - Integrated into `TransitiveDependencyAuditor.annotate_reachability()` and CLI `mcp-vuln audit-transitive --source-dir <path> [--reachable-only]`.
3. **Wave 15 Web Portal & Multi-Dimensional Analytics Remediation (Tasks 78–83)**:
   - Precomputed `highest_cve_severity` and `composite_risk_tier` in `mcp_catalog_index.json` (`site_builder.py`).
   - Latest-version (`versions[-1]`) tool, capability surface, and secrets perimeter extraction in `site_builder.py`.
   - In-browser Config Auditor enrichment with CVE/GHSA IDs, CVSS scores, severity badges, and safe-version pin detection (`docs/app.js`).
   - Complete CSS `:root` design tokens (`--bg-tertiary`, `--primary-color`, `--bg-card`, `--bg-hover`, `--badge-bg`, `.badge-eco`), accessible `.fp-badge` controls, primitive sub-tab reset on version selection, and SVG sparkline `viewBox="0 0 1000 80"`.

This task synchronizes all repository documentation (`README.md`, `docs/SPECIFICATION.md`, `docs/IMPLEMENTATION.md`, `CHANGELOG.md`, and `docs/tasks/README.md`) with these v1.2.0 features.

---

## 2. Target Files & Isolation Boundaries

- **Primary Files:**
  - `README.md`
  - `docs/SPECIFICATION.md`
  - `docs/IMPLEMENTATION.md`
  - `CHANGELOG.md`
  - `docs/tasks/README.md`
- **Do NOT Modify:** `docs/reports/code_review_*.md` (owned by Task 86 in parallel) or `tests/conftest.py` (do not create `tests/conftest.py`).

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: CLI & Architecture Documentation Completeness (`INVARIANT_87_1A` – `INVARIANT_87_1D`)
- **Invariants**:
  - [ ] **INVARIANT_87_1A (`README.md` v1.2 CLI Examples)**: `README.md` documents `mcp-vuln proxy` (with `--package`, `--version`, `--block-severity`, `--redact-secrets`, `--audit-log`, `-- <cmd>`) and `mcp-vuln audit-transitive --source-dir <dir> --reachable-only`, and reflects version `1.2.0` and `370+` automated tests.
  - [ ] **INVARIANT_87_1B (`docs/SPECIFICATION.md` Formal Contracts)**: `docs/SPECIFICATION.md` specifies:
    - The Inline MCP Reverse Proxy JSON-RPC 2.0 interception contract, error code `-32001` response schema, and JSONL audit log schema.
    - The AST Call-Graph Reachability classification model (`REACHABLE_FROM_TOOL`, `IMPORTED_ONLY`, `UNREACHABLE`) and package-to-import alias resolution rules.
    - The `highest_cve_severity` and `composite_risk_tier` schema fields on `mcp_catalog_index.json`.
  - [ ] **INVARIANT_87_1C (`docs/IMPLEMENTATION.md` Module Architecture)**: `docs/IMPLEMENTATION.md` documents `src/mcp_vulnerabilities/proxy/` (`policy.py`, `interceptor.py`), `src/mcp_vulnerabilities/analyzers/reachability/` (`call_graph.py`), and the Wave 15 `site_builder.py` / `docs/app.js` enhancements.
  - [ ] **INVARIANT_87_1D (`CHANGELOG.md` & `docs/tasks/README.md` Sync)**:
    - `CHANGELOG.md` includes a comprehensive `## [1.2.0] - 2026-10-25` section detailing Wave 15 (Tasks 78–83), Wave 16 (Tasks 84–85), and Wave 17 (Tasks 86–88).
    - `docs/tasks/README.md` accurately lists Tasks 78–85 as `Done` (including Task 82 CSS/UI Hygiene and Task 83 Automated Test Suite) and includes Section 17 for Wave 17 (Tasks 86–88).

---

## 4. Concrete Implementation Instructions

1. Update `README.md` to showcase `mcp-vuln proxy` and `mcp-vuln audit-transitive --source-dir --reachable-only` in the CLI Reference and Feature Highlights sections.
2. Update `docs/SPECIFICATION.md` with dedicated sections for the v1.2 Inline MCP Reverse Proxy Interceptor, AST Interprocedural Call-Graph Reachability Engine, and `mcp_catalog_index.json` composite risk fields.
3. Update `docs/IMPLEMENTATION.md` with architectural diagrams and component breakdowns for `proxy/`, `analyzers/reachability/`, and the Wave 15 portal/analytics pipeline.
4. Prepend `## [1.2.0] - 2026-10-25` to `CHANGELOG.md` covering all Wave 15, Wave 16, and Wave 17 deliverables.
5. Update `docs/tasks/README.md` Sections 15, 16, and 17 so all tasks (78–88) and verification metrics are up to date.
6. Do **NOT** create `tests/conftest.py`.

---

## 5. Non-Interactive Completion Directive

Complete all documentation updates thoroughly, preserve existing unrelated documentation sections, and commit directly without asking open-ended questions so the session cleanly transitions to `Completed`.

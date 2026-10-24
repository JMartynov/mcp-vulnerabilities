# Task 85: v1.2 AST Interprocedural Call-Graph Reachability Engine (P1)

**Blueprint Reference:** v1.2 Strategic Roadmap Blueprint 2 ([`docs/audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md`](../audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md) & [`docs/audit/competitive_snyk_semgrep_trivy_osv.md`](../audit/competitive_snyk_semgrep_trivy_osv.md))  
**Target Wave:** Wave 16 (v1.2 Strategic Runtime & Reachability Engines)  
**Priority:** `P1` (Core v1.2 Context-Aware SCA & Reachability Feature)

---

## 1. Architectural Context & Technical Objective

Competitive benchmarking against Snyk, Semgrep Supply Chain, Trivy, and Google OSV-Scanner (`Task 69` / `Task 72`) highlighted a key gap in `mcp-vuln audit-transitive`: lockfile and manifest scanning (`package.json`, `pyproject.toml`, `uv.lock`, `poetry.lock`, `requirements.txt`) flags every transitive dependency vulnerability regardless of whether the MCP server's exposed tools ever import or invoke that dependency. In enterprise DevSecOps pipelines, this creates high false-positive alert fatigue when a vulnerable package or function is either never imported or only referenced inside dead/non-tool code paths.

This task implements the **AST Interprocedural Call-Graph Reachability Engine** (`src/mcp_vulnerabilities/analyzers/reachability/`) and integrates it with `TransitiveDependencyAuditor` (`src/mcp_vulnerabilities/transitive.py`) and `mcp-vuln audit-transitive`:
1. **MCP Tool Entrypoint Discovery**: Parses Python (`.py` via `ast`) and JavaScript/TypeScript (`.js`/`.ts` via structural AST regex/token parsing) files to identify exposed MCP tool entrypoints (`@mcp.tool`, `@server.call_tool`, `server.tool(...)`, `McpServer.tool(...)`, or functions registered in tool dispatch tables).
2. **Import & Symbol Alias Resolution**: Maps top-level and function-scoped third-party package imports (`import pkg`, `from pkg.sub import sym as alias`, `require('pkg')`, `import { sym } from 'pkg'`) to canonical package names (normalizing PyPI `_` / `-` and common import aliases such as `yaml` ➔ `pyyaml`, `PIL` ➔ `pillow`, `bs4` ➔ `beautifulsoup4`).
3. **Interprocedural Call-Graph Traversal (DFS)**: Builds a function-to-function call graph across the source directory and performs Depth-First Search (DFS) starting from all discovered MCP tool entrypoints (or module entrypoints if no explicit decorators exist) to determine which local functions and third-party imported packages/symbols are reachable.
4. **Reachability Classification**: Classifies every dependency finding as:
   - `"REACHABLE"`: Imported and invoked along a call path originating from an exposed MCP tool entrypoint (or matching specific `ecosystem_specific.imports` / vulnerable symbols when present).
   - `"UNREACHABLE_IMPORT"`: Imported in the codebase, but only inside dead/uncalled functions that have no call path from any MCP tool entrypoint.
   - `"NOT_IMPORTED"`: Present in the lockfile/manifest, but never imported anywhere in the server source tree.

---

## 2. Target Files & Isolation Boundaries

- **New Package Files:**
  - `src/mcp_vulnerabilities/analyzers/reachability/__init__.py`
  - `src/mcp_vulnerabilities/analyzers/reachability/call_graph.py`
- **Transitive & CLI Integration:**
  - `src/mcp_vulnerabilities/transitive.py` (add `reachability: str = "UNKNOWN"` and `reachable_from_tools: list[str]` to `TransitiveFinding`, plus `annotate_reachability()` on `TransitiveAuditResult`)
  - `src/mcp_vulnerabilities/cli.py` (extend `audit-transitive` with `--source-dir <dir>` and `--reachable-only`)
- **Test Suite:**
  - `tests/test_ast_reachability.py`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Multi-Hop Interprocedural Call-Graph Traversal (`INVARIANT_85_1A`)
- **Preconditions**: A Python MCP server defines:
  - `@mcp.tool() def query_data(q: str): return helper_a(q)`
  - `def helper_a(x): return helper_b(x)`
  - `def helper_b(y): return requests.get(y)`
  - `def unused_dead_func(): return jinja2.Template("...")`
  - And `urllib3` is listed in `requirements.txt` but never imported.
- **Invariants**:
  - [ ] **INVARIANT_85_1A (Multi-Hop Reachable Detection)**: `AstReachabilityAnalyzer` traces `query_data ➔ helper_a ➔ helper_b ➔ requests.get`, classifying `requests` as `reachability="REACHABLE"` with `reachable_from_tools=["query_data"]` and `called_symbols=["requests.get"]`.
  - [ ] **INVARIANT_85_1B (Dead Function Isolation)**: `jinja2` (used only inside `unused_dead_func`, which is never called by `query_data` or module top-level) is classified as `reachability="UNREACHABLE_IMPORT"`.
  - [ ] **INVARIANT_85_1C (Unimported Lockfile Dependency)**: `urllib3` is classified as `reachability="NOT_IMPORTED"`.

### Scenario 2: JavaScript / TypeScript MCP Tool Reachability (`INVARIANT_85_2A`)
- **Preconditions**: A TypeScript/JavaScript MCP server registers `server.tool("fetch_doc", schema, async (args) => { return fetchHelper(args.url); })` where `fetchHelper` calls `axios.get(url)`, while `lodash` is imported at the top of the file and only referenced inside an uncalled `legacyFormat()` function.
- **Invariants**:
  - [ ] **INVARIANT_85_2A (JS/TS Tool Entrypoint & Call Graph)**: `axios` is classified as `"REACHABLE"` from `"fetch_doc"`, and `lodash` is classified as `"UNREACHABLE_IMPORT"`.

### Scenario 3: `TransitiveDependencyAuditor` & CLI Integration (`INVARIANT_85_3A`)
- **Preconditions**: Run `TransitiveDependencyAuditor` with `source_dir` provided (and `mcp-vuln audit-transitive <manifest> --source-dir <dir> [--reachable-only]`).
- **Invariants**:
  - [ ] **INVARIANT_85_3A (Finding Annotation)**: Each `TransitiveFinding` includes `reachability` (`"REACHABLE" | "UNREACHABLE_IMPORT" | "NOT_IMPORTED" | "UNKNOWN"`) and `reachable_from_tools: list[str]`, serialized in `TransitiveAuditResult.to_dict()`.
  - [ ] **INVARIANT_85_3B (`--reachable-only` Filtering)**: Passing `--reachable-only` filters `result.findings` to retain only findings with `reachability == "REACHABLE"` (and updates `has_critical_or_high` accordingly).

---

## 4. Concrete Implementation Instructions

1. Create `src/mcp_vulnerabilities/analyzers/reachability/call_graph.py`:
   - Define `DependencyReachability(package_name: str, status: str, reachable_from_tools: list[str], called_symbols: list[str])` and `ReachabilityReport` dataclasses.
   - Implement `AstReachabilityAnalyzer`:
     - `analyze_directory(source_dir: str | Path) -> ReachabilityReport`
     - `evaluate_package(package_name: str, report: ReachabilityReport, vulnerable_symbols: list[str] | None = None) -> DependencyReachability`
   - Support Python `ast` parsing (detecting `@mcp.tool`, `@server.call_tool`, `@app.tool`, `@tool`, `CallToolRequest` handlers, function definitions, imports, and interprocedural calls) and JS/TS source analysis (`server.tool(...)`, `setRequestHandler(CallToolRequestSchema, ...)`, `import`/`require`, and function calls).
2. Update `src/mcp_vulnerabilities/transitive.py`:
   - Add `reachability: str = "UNKNOWN"` and `reachable_from_tools: list[str] = field(default_factory=list)` to `TransitiveFinding` and include them in `TransitiveAuditResult.to_dict()`.
   - Add `annotate_reachability(result: TransitiveAuditResult, source_dir: str | Path, reachable_only: bool = False) -> TransitiveAuditResult`.
3. Update `src/mcp_vulnerabilities/cli.py`:
   - Add `--source-dir` and `--reachable-only` arguments to `audit-transitive` (`trans_p`) and wire them into `_cmd_audit_transitive()`.
4. Create `tests/test_ast_reachability.py` testing Python 3-hop call graphs, dead functions, unimported packages, package alias resolution (`pyyaml`/`yaml`, `pillow`/`PIL`), JS/TS MCP servers, and CLI `--source-dir` / `--reachable-only` integration.

---

## 5. Non-Interactive Completion Directive

Complete all implementation steps, verify all tests pass locally via `.venv/bin/pytest -q`, and commit directly without asking open-ended questions so the session cleanly transitions to `Completed`.

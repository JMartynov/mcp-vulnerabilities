# Task 26 Contract: MCP Production Readiness & Schema Contract Linter

## Objective
Implement a comprehensive, zero-dependency static linter (`mcp-vuln lint`) that audits MCP tool schemas, prompt templates, and protocol interfaces for production readiness, contract hygiene, and resilience. The linter prevents AI agent hallucinations, runtime execution timeouts, and protocol failures by enforcing schema completeness, parameter typing, and robust documentation standards.

> [!IMPORTANT]
> **STRICT LIVE EXECUTION REQUIREMENT (NO MOCKS)**: Acceptance scenarios MUST be 100% live — executing against 50+ authentic server passports loaded from `data/passports.json.gz`, real temporary schema files written to disk, and real CLI subprocess invocations. Do NOT use `unittest.mock` or `@patch` for acceptance tests.

---

## Detailed Technical Architecture & Implementation

### 1. Subsystem Location: `src/mcp_vulnerabilities/analyzers/`
Add `readiness.py` to `src/mcp_vulnerabilities/analyzers/`:
- `models.py`:
  - `ReadinessIssue`: Data class containing `rule_id`, `severity` (`CRITICAL`, `WARNING`, `INFO`), `target` (e.g. `tool:search_records.param:limit`), `message`, and `recommendation`.
  - `ReadinessReport`: Contains `target_name`, `score` (0 to 100), `grade` (`A`, `B`, `C`, `D`, `F`), `issues` (list of `ReadinessIssue`), and `summary_counts`.
- `readiness.py`:
  - `ReadinessLinter`: Core evaluation engine implementing the following rule catalog:
    1. **`MCP-R001` (Missing/Vague Tool Description)**: Flags tools with no description, whitespace-only descriptions, or descriptions under 12 characters (which cause severe agent invocation failure).
    2. **`MCP-R002` (Untyped or Broad Parameters)**: Flags parameters lacking explicit JSON schema types or configured with unconstrained `"type": "any"`.
    3. **`MCP-R003` (Missing Required Parameter Specification)**: Flags object schemas lacking an explicit `required: [...]` array, leading to ambiguous client calls.
    4. **`MCP-R004` (Parameter Description Absence)**: Flags required parameters with zero explanatory text for the model.
    5. **`MCP-R005` (Unbounded Collection Parameters)**: Flags arrays without `items` definitions or integer inputs without `minimum`/`maximum` bounds.
    6. **`MCP-R006` (Naming Collision & Convention Violation)**: Flags tools using non-standard naming (spaces, illegal characters, uppercase) or overlapping with standard platform commands.
    7. **`MCP-R007` (Mutating Tool Error Contract Absence)**: Flags tools marked as mutating (`is_mutating: true` or destructive verb prefixes) that do not specify an `outputSchema` or failure responses.
  - Scoring algorithm: Computes a deterministic weighted score based on issue severity deductions:
    - CRITICAL: -20 points
    - WARNING: -5 points
    - INFO: -1 point
    - Grade calculation: A (90-100), B (80-89), C (70-79), D (60-69), F (<60).

### 2. CLI Integration
- In `src/mcp_vulnerabilities/cli.py`:
  - Add subcommand `lint`:
    ```bash
    mcp-vuln lint --command "uvx mcp-server-fetch"
    mcp-vuln lint --url "http://127.0.0.1:8000/sse"
    mcp-vuln lint --file ./mcp_schema.json
    ```
  - Add `--readiness` flag to `mcp-vuln probe`: Injects the readiness scorecard into standard probe results.
  - Formatting: Emits a visual terminal scorecard with colored letter grade, breakdown of passed/failed checks, and actionable remediation steps.

---

## Clear Acceptance Criteria

1. **Deterministic Rule Enforcement**:
   - Accurately detects and categorizes all 7 rule violations on arbitrary MCP JSON schemas.
2. **Standardized Scoring System**:
   - Emits consistent 0-100 scores and letter grades (A through F) with zero floating-point nondeterminism.
3. **Multi-Input Flexibility**:
   - Supports linting directly from live stdio commands, live SSE URLs, raw JSON files, or Python dictionaries.
4. **SARIF and CI/CD Gating**:
   - Supports `--format sarif` and `--fail-under <score>` flag to fail CI/CD pipelines when schema quality drops below threshold.
5. **Zero External Dependencies**:
   - Implemented purely in Python standard library (`json`, `dataclasses`, `re`, `typing`).

---

## Comprehensive Test Plan

### A. Unit Tests (`tests/test_readiness.py`)
- Test individual rule triggers against positive and negative schema fixtures.
- Test scoring deductions and grade boundary edge cases (89 vs 90).
- Test CLI argument parsing and `--fail-under` exit codes.

### B. Live Acceptance Tests (Zero Mocks — Real Passports & Real Files)
- `test_live_lint_passports_sample`: Load 50 real, production MCP server passports from `data/passports.json.gz`. Run the readiness linter across all 50 live schemas. Verify that the linter completes in < 2 seconds, produces valid `ReadinessReport` objects for all 50 servers, and outputs realistic distributions of grades.
- `test_live_lint_cli_file_execution`: Write a real temporary `mcp_schema.json` file to disk containing known defects (untyped parameters and missing descriptions). Execute the CLI `mcp-vuln lint --file <path>` in a real subprocess. Verify exit code, stdout formatting, and error annotations.
- `test_live_lint_stdio_server`: Spin up a real local Python MCP test script via stdio. Run `mcp-vuln lint --command "python3 <script>"` and verify live tool schemas are inspected, scored, and graded.

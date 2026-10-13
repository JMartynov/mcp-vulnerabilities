# Task 28 Contract: Static AST Source Code Taint & Dangerous Sink Analyzer

## Objective
Implement a high-precision static source code analysis engine (`mcp-vuln scan-source`) using Python's native Abstract Syntax Tree (`ast`) module. The engine audits local MCP server repositories by tracing dataflow from tool input parameters (taint sources) into dangerous operating system, execution, and filesystem operations (taint sinks), discovering vulnerabilities prior to runtime deployment.

> [!IMPORTANT]
> **STRICT LIVE EXECUTION REQUIREMENT (NO MOCKS)**: Acceptance scenarios MUST be 100% live — parsing and scanning real Python files on disk containing authentic `@mcp.tool` code, asserting exact AST taint detection, and verifying real SARIF JSON output via live subprocess execution. Do NOT use `unittest.mock` or `@patch` for acceptance tests.

---

## Detailed Technical Architecture & Implementation

### 1. Subsystem Location: `src/mcp_vulnerabilities/analyzers/ast_taint/`
Create package `src/mcp_vulnerabilities/analyzers/ast_taint/` with:
- `models.py`:
  - `TaintSinkCategory`: Enum (`COMMAND_INJECTION`, `CODE_EVALUATION`, `PATH_TRAVERSAL`, `SQL_INJECTION`, `SSRF_EGRESS`).
  - `TaintFinding`: Captures `tool_name`, `parameter_name`, `source_line`, `sink_call`, `sink_category`, `sink_line`, `severity` (`CRITICAL`, `HIGH`, `MEDIUM`), `code_snippet`, and `remediation`.
- `visitor.py`:
  - `McpToolAstVisitor`: Recursively walks Python AST nodes:
    1. **Tool Entrypoint Detection**: Identifies functions decorated with `@mcp.tool`, `@server.tool`, `@app.tool`, `@tool`, or registered via `FastMCP` patterns.
    2. **Source Taint Marking**: Marks all function parameters as tainted input variables.
    3. **Intra-procedural Dataflow Tracking**: Tracks taint propagation across:
       - Variable assignments (`cmd = f"ping {user_input}"`).
       - String formatting (`%` formatting, `.format()`, f-strings `JoinedStr`).
       - Binary operations and concatenation (`"cat " + path`).
       - Collection packing/unpacking (tuples, lists, dicts).
    4. **Sink Call Matching**: Detects calls where tainted variables reach critical sinks:
       - `COMMAND_INJECTION`: `os.system`, `subprocess.run`, `subprocess.Popen`, `subprocess.check_output`, `os.popen`, `pty.spawn`.
       - `CODE_EVALUATION`: `eval`, `exec`, `compile`, `builtins.__import__`.
       - `PATH_TRAVERSAL`: `open`, `os.remove`, `os.unlink`, `shutil.rmtree`, `pathlib.Path.write_text`, `pathlib.Path.read_text` with unvalidated path construction.
       - `SQL_INJECTION`: `cursor.execute`, `connection.execute` when receiving dynamic f-strings rather than parameterized queries.
       - `SSRF_EGRESS`: `urllib.request.urlopen`, `requests.get/post`, `httpx.get/post` targeting unvalidated parameter URLs.
- `scanner.py`:
  - `McpSourceScanner`: Recursively traverses local directories, skips `.venv` and `__pycache__`, parses `.py` files, aggregates findings, and computes overall repository risk score.

### 2. CLI Integration
- In `src/mcp_vulnerabilities/cli.py`:
  - Add subcommand `scan-source`:
    ```bash
    mcp-vuln scan-source ./server/ --format sarif --output results.sarif
    ```
  - Options:
    - `--fail-on {CRITICAL,HIGH}`: CI/CD gating flag.
    - `--format {text,json,sarif}`: Emits SARIF v2.1.0 with exact file paths and line ranges for GitHub Code Scanning annotations.

---

## Clear Acceptance Criteria

1. **Zero-Dependency Native Parsing**:
   - Built entirely on Python's built-in `ast` module; no external binary parsers or compiler dependencies required.
2. **High Precision Injection Discovery**:
   - Detects command injection, code evaluation, and path traversal in MCP tools with exact line and column numbers.
3. **Dataflow Propagation Fidelity**:
   - Correctly traces taint across variable reassignments, f-strings, and string formatting expressions.
4. **Clean Code Baseline**:
   - Produces zero false positives on properly parameterized functions (e.g. `subprocess.run(["ls", "-la"])` with fixed strings).
5. **Standardized SARIF Emission**:
   - Generates fully compliant OASIS SARIF v2.1.0 reports ready for immediate upload to GitHub Security Tab.

---

## Comprehensive Test Plan

### A. Unit Tests (`tests/test_ast_taint.py`)
- Test decorator detection across `@mcp.tool()`, `@mcp.tool`, and custom tool decorators.
- Test f-string taint propagation logic (`ast.JoinedStr`).
- Test detection of sanitized versus unsanitized `subprocess.run` calls.

### B. Live Acceptance Tests (Zero Mocks — Real Python Source Code on Disk)
- `test_live_command_injection_detection`: Write a real Python file to disk declaring a `@mcp.tool()` function that executes `subprocess.Popen(f"curl {url}")`. Run `McpSourceScanner` against the live file. Verify that a `CRITICAL` finding of category `COMMAND_INJECTION` is flagged with exact line numbers and code snippets.
- `test_live_clean_tool_no_false_positives`: Write a real Python file declaring a safe `@mcp.tool()` function using parameterized queries and strictly validated inputs. Run the scanner and verify that zero findings are produced.
- `test_live_cli_scan_source_sarif`: Execute `mcp-vuln scan-source <path> --format sarif` in a real subprocess against a sample directory. Verify that the emitted SARIF JSON parses successfully against the OASIS SARIF v2.1.0 JSON schema.

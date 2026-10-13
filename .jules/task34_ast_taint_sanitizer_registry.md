# Task Specification: AST Taint Sanitizer Registry & Inter-Procedural Propagation (P1-3)

## Objective
Enhance the static AST source code taint analyzer (`src/mcp_vulnerabilities/analyzers/ast_taint/`) to:
1. **Eliminate False Positives via Sanitizer Registry**: Recognize standard de-tainting and sanitization functions (`shlex.quote`, `re.escape`, `os.path.basename`, `int`, `float`, `pathlib.Path.resolve`, `html.escape`, `urllib.parse.quote`). When a tainted tool parameter passes through a recognized sanitizer, it is removed from the active taint set.
2. **Expand Coverage via Intra-Module Call Graph**: Track parameter delegation from `@mcp.tool` functions to local helper functions within the same Python module. If `tool_foo(cmd)` passes `cmd` to `_execute_helper(c)` which invokes `subprocess.run(c)`, the sink in `_execute_helper` must be correctly flagged as a tainted command injection.

## Target Files
- `src/mcp_vulnerabilities/analyzers/ast_taint/visitor.py`
- `src/mcp_vulnerabilities/analyzers/ast_taint/models.py`
- `src/mcp_vulnerabilities/analyzers/ast_taint/scanner.py`
- `tests/test_ast_taint_sanitizers.py`
- `tests/test_acceptance_ast_taint.py`

## Implementation Details
1. **In `src/mcp_vulnerabilities/analyzers/ast_taint/models.py`**:
   - Add `KNOWN_SANITIZERS`:
     ```python
     KNOWN_SANITIZERS = {
         # Shell injection sanitizers
         "shlex.quote": {SinkCategory.COMMAND_INJECTION},
         "quote": {SinkCategory.COMMAND_INJECTION},
         # Path traversal sanitizers
         "os.path.basename": {SinkCategory.PATH_TRAVERSAL},
         "basename": {SinkCategory.PATH_TRAVERSAL},
         "pathlib.Path.resolve": {SinkCategory.PATH_TRAVERSAL},
         # Numeric casts sanitize command, eval, sql, ssrf, traversal
         "int": {SinkCategory.COMMAND_INJECTION, SinkCategory.SQL_INJECTION, SinkCategory.PATH_TRAVERSAL, SinkCategory.CODE_EVALUATION},
         "float": {SinkCategory.COMMAND_INJECTION, SinkCategory.SQL_INJECTION, SinkCategory.PATH_TRAVERSAL, SinkCategory.CODE_EVALUATION},
         # RegEx / URL sanitizers
         "re.escape": {SinkCategory.COMMAND_INJECTION},
         "urllib.parse.quote": {SinkCategory.SSRF_EGRESS},
     }
     ```
2. **In `src/mcp_vulnerabilities/analyzers/ast_taint/visitor.py`**:
   - In `visit_Call`: Check if the call is a registered sanitizer. If so, return a de-tainted node marker so the assigned variable is excluded from the taint set for that sink category.
   - Implement `visit_Module`: First pass constructs a map of function definitions `self.functions: dict[str, ast.FunctionDef]`. When an `@mcp.tool` function calls a local function, propagate tainted arguments into the target function's parameter symbols and inspect its body.
3. **Keep Visitor Clean & Zero-Dependency**:
   - Rely solely on standard library `ast`.

## Acceptance Criteria (100% Live & Unmocked)
1. **Live Sanitizer Test (`tests/test_ast_taint_sanitizers.py`)**:
   - Inspect a sample Python tool using `safe_cmd = f"ls {shlex.quote(user_input)}"; subprocess.run(safe_cmd, shell=True)`.
   - Verify it is evaluated as CLEAN (zero vulnerabilities reported).
   - Inspect an unsanitized tool `bad_cmd = f"ls {user_input}"; subprocess.run(bad_cmd, shell=True)`.
   - Verify it is flagged as `COMMAND_INJECTION` (Critical).
2. **Live Helper Function Delegation Test**:
   - Inspect a Python module where `@mcp.tool def my_tool(p): return _internal_eval(p)` and `def _internal_eval(val): eval(val)`.
   - Verify `CODE_EVALUATION` vulnerability is detected and traces back to `p`.
3. All existing tests in `tests/test_ast_taint.py` and `tests/test_acceptance_ast_taint.py` continue to pass.

## Non-Interactive Completion Directive
Execute all changes, write tests, run the test suite, ensure all tests pass with zero errors, and commit cleanly without asking interactive questions.

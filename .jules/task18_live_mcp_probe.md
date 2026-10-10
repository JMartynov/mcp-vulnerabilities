### Task: Live MCP Protocol Probe & Tool Auditor (cli probe)

#### 1. Architectural Context & Purpose:
Static auditing inspects package names in configuration files or lockfiles, but cannot inspect dynamic, in-memory, or custom-built MCP servers running locally or hosted remotely over SSE/HTTP.
The Model Context Protocol (MCP) specifies a standard JSON-RPC 2.0 handshake (`initialize`, `notifications/initialized`) followed by capability discovery (`tools/list`, `resources/list`, `prompts/list`).
This task implements a dynamic protocol probe CLI command (`mcp-vuln probe`) that actively connects to a target MCP server over `stdio` (subprocess execution) or `sse` (HTTP/SSE endpoint), executes the standard handshake, extracts declared tool definitions, and fingerprints the running server against our 519+ curated MCP vulnerability signatures.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/probe/`: New module containing `transport.py`, `client.py`, and `fingerprinter.py`.
* `src/mcp_vulnerabilities/audit/matcher.py`: Correlates detected server metadata and tools with advisories.
* `src/mcp_vulnerabilities/cli.py`: Add subcommand `probe`.
* `src/mcp_vulnerabilities/models.py`: OSV models and vulnerable tools tags.

#### 3. Engineering & Implementation Blueprint:
1. **Create `src/mcp_vulnerabilities/probe/transport.py`**:
   - `StdioTransport`: Spawns the server process via `subprocess.Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE, text=True)`.
     - Sends newline-delimited JSON-RPC messages.
     - Reads responses with configurable timeouts (default 5.0 seconds).
   - `HttpSseTransport`: (Optional/extensible) Communicates with SSE servers using Python standard library `urllib.request`.
2. **Create `src/mcp_vulnerabilities/probe/client.py`**:
   - `McpProbeClient`:
     - Executes `initialize`:
       ```json
       {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "mcp-vuln-probe", "version": "1.0.0"}}}
       ```
     - Extracts `serverInfo`: `name`, `version`.
     - Sends `notifications/initialized`.
     - Queries `tools/list`:
       ```json
       {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
       ```
     - Collects tool list: names, descriptions, input schemas.
     - Gracefully terminates subprocess or connection.
3. **Create `src/mcp_vulnerabilities/probe/fingerprinter.py`**:
   - `McpFingerprinter`:
     - Compares `serverInfo.name` and `serverInfo.version` against `VulnerabilityMatcher`.
     - Scans declared tools against known vulnerable tool names recorded across advisories (e.g. `cypher_query`, `write_file`, `shell_exec`, `execute_command`, `evaluate_code`).
     - Emits `ProbeAuditReport` containing:
       - Server name & reported version.
       - Confirmed package vulnerabilities (if version in affected range).
       - Declared high-risk tool warnings (e.g. tools matching dangerous MCP capabilities without proper sandboxing or known CVEs).
4. **In `src/mcp_vulnerabilities/cli.py`**:
   - Add subcommand `probe`:
     ```bash
     mcp-vuln probe --command "python server.py" [--timeout 5] [--format table|json]
     mcp-vuln probe --url "http://localhost:8000/sse" [--format table|json]
     ```
   - Render informative terminal summary table or JSON.
5. **Unit Tests**:
   - Add `tests/test_probe.py`:
     - Test mock stdio server implementing JSON-RPC 2.0 handshake and `tools/list`.
     - Assert server info parsing, tool extraction, vulnerability matching, and timeout handling.

#### 4. Guardrails & Security Invariants:
* **Strict Timeout Protection**: Subprocesses must be killed with `SIGTERM` / `SIGKILL` if they fail to complete the handshake within the specified timeout.
* **Non-Invasive Inspection**: The probe only calls `initialize` and read-only discovery methods (`tools/list`). It NEVER executes server tools or sends `tools/call`.

#### 5. Acceptance Criteria:
- [ ] `mcp-vuln probe --command "..."` connects to a stdio MCP server, performs the JSON-RPC handshake, and extracts `tools/list`.
- [ ] Accurately detects server version and flags known vulnerabilities if the version is affected.
- [ ] Flags high-risk tool declarations matching known vulnerable tool signatures.
- [ ] Subprocess terminates cleanly upon completion or timeout without hanging.
- [ ] Unit tests in `tests/test_probe.py` pass with 100% assertions satisfied using a mock stdio server.

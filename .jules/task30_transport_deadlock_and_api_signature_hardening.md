# Task Specification: Subprocess Stderr Deadlock Elimination & API Daemon Transport Signature Hardening (P0-1 & P0-2)

## Objective
Remediate two critical production reliability issues in the MCP transport and API daemon:
1. **Unconsumed Subprocess Stderr Deadlock**: In `src/mcp_vulnerabilities/probe/transport.py`, `StdioTransport.start()` launches subprocesses with `stderr=subprocess.PIPE` without reading from it. When an MCP server outputs >64KB of diagnostic logs or stack traces to stderr, the OS pipe buffer saturates, causing the process to deadlock permanently. Implement a non-blocking background reader thread that drains `stderr` into an in-memory rotating ring buffer (e.g. `collections.deque(maxlen=100)`), capturing diagnostic lines that are preserved and surfaced upon abnormal process exit.
2. **API Daemon Command Signature Mismatch**: In `src/mcp_vulnerabilities/api/routes.py` (lines 64 & 131), the server instantiates `StdioTransport(command=cmd_parts[0], args=cmd_parts[1:])`. However, `StdioTransport.__init__` in `transport.py` currently only accepts `command: str`, throwing `TypeError: StdioTransport.__init__() got an unexpected keyword argument 'args'` and HTTP 500 when command parameters are submitted to `/api/v1/scan/probe` or `/api/v1/identify`. Update `StdioTransport.__init__` to accept `command: str, args: list[str] | None = None, env: dict[str, str] | None = None` and properly format the execution command array.

## Target Files
- `src/mcp_vulnerabilities/probe/transport.py`
- `src/mcp_vulnerabilities/api/routes.py`
- `tests/test_acceptance_transport_deadlock.py`
- `tests/test_api_server.py`

## Implementation Details
1. **In `src/mcp_vulnerabilities/probe/transport.py`**:
   - Update `StdioTransport.__init__(self, command: str, args: list[str] | None = None, env: dict[str, str] | None = None, cwd: str | None = None)`:
     - If `args` is provided, the full command array is `[command] + list(args)`. If `args` is None, use `shlex.split(command)`.
     - Initialize `self.stderr_buffer = collections.deque(maxlen=100)`.
     - Initialize `self._stderr_thread = None`.
   - In `start()`:
     - Launch daemon thread `self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)`.
     - `_drain_stderr()` reads lines continuously until EOF:
       ```python
       def _drain_stderr(self):
           if not self.process or not self.process.stderr:
               return
           try:
               for line in iter(self.process.stderr.readline, ""):
                   if not line:
                       break
                   self.stderr_buffer.append(line.rstrip())
           except Exception:
               pass
       ```
   - In `stop()`:
     - Close `self.process.stderr` and `stdin` and `stdout` cleanly.
     - Provide property `last_stderr_lines -> list[str]` to inspect captured stderr logs.
2. **In `src/mcp_vulnerabilities/api/routes.py`**:
   - Ensure `StdioTransport` calls pass `cmd_parts[0]` and `args=cmd_parts[1:]` cleanly.
   - If an error occurs during probing, include `transport.last_stderr_lines` in the error response payload when available for easier debugging.

## Acceptance Criteria (100% Live & Unmocked)
1. **Unmocked Stderr Flood Test (`tests/test_acceptance_transport_deadlock.py`)**:
   - Launch a live Python subprocess via `sys.executable` that writes 256KB of text to `sys.stderr` while simultaneously replying to MCP JSON-RPC `initialize` on stdout.
   - Verify `StdioTransport` connects, completes the handshake without deadlocking, and captures the latest stderr lines in `stderr_buffer`.
2. **Live API Daemon Command Probe Test**:
   - Send live HTTP POST request to `/api/v1/scan/probe` with a command array (e.g. `[sys.executable, "-c", "..."]`).
   - Verify it executes without `TypeError` or HTTP 500, returning a valid 200 OK scan report over the local TCP socket.
3. All existing tests in `tests/test_api_server.py` and `tests/test_acceptance_stdio_probe.py` must pass.

## Non-Interactive Completion Directive
Execute all changes, write tests, run the test suite, ensure all tests pass with zero errors, and commit cleanly without asking interactive questions.

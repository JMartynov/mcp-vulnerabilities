# Task 25 Contract: Full-Surface Protocol Probe & Live SSE / Streamable HTTP Transport Engine

## Objective
Upgrade the runtime MCP probing infrastructure from a local stdio-only tool into a comprehensive, multi-transport, full-surface protocol inspector. Implement production-grade Server-Sent Events (SSE) and Streamable HTTP transports, custom authentication header support, and expand the discovery surface to capture `tools/list`, `prompts/list`, `resources/list`, and server `instructions`.

> [!IMPORTANT]
> **STRICT LIVE EXECUTION REQUIREMENT (NO MOCKS)**: Acceptance scenarios MUST be 100% live — running against live localhost TCP sockets with real HTTP/SSE event streams, authentic Bearer token auth challenges, and real Python subprocess stdio pipes. Do NOT use `unittest.mock` or `@patch` for acceptance tests.

---

## Detailed Technical Architecture & Implementation

### 1. Subsystem Enhancements: `src/mcp_vulnerabilities/probe/`
Update and expand `src/mcp_vulnerabilities/probe/`:
- `transport.py`:
  - Replace the `HttpSseTransport` stub (`raise NotImplementedError`) with a robust, streaming HTTP/SSE transport client:
    - **SSE Connection Management**: Opens HTTP connection with `Accept: text/event-stream`. Parses incoming event chunks (`event: endpoint`, `data: <json_rpc_url>`), establishing bidirectional message flow.
    - **Streamable HTTP POST Channel**: Sends JSON-RPC requests via HTTP POST to the discovered RPC endpoint or base URL with `Content-Type: application/json`.
    - **Header & Auth Injection**: Accepts dictionary of custom HTTP headers: `--header "Key: Value"` and `--auth-header "Authorization: Bearer <token>"`.
    - **Connection Resilience**: Implements configurable connect and read timeouts (`timeout: float`), graceful stream closing, and clear transport error handling (`TransportTimeoutError`, `TransportAuthError`, `TransportProtocolError`).
- `client.py`:
  - Refactor `McpProbeClient` to perform **Full-Surface Discovery**:
    1. Sends `initialize` handshake with protocol version `2024-11-05` and full client capabilities.
    2. Inspects `initialize` response for:
       - `serverInfo`: name, version.
       - `capabilities`: checks for `prompts`, `resources`, `tools`, and `logging`.
       - `instructions`: captures server-level instructions or system prompts.
    3. Sends `notifications/initialized`.
    4. Concurrently or sequentially queries all supported surface endpoints:
       - `tools/list`: retrieves all registered tools and JSON schemas.
       - `prompts/list`: retrieves all registered prompt templates and argument schemas (if supported by server capabilities).
       - `resources/list`: retrieves all registered exposed resources and URIs (if supported).
    5. Stores findings in a structured `DiscoveredMcpSurface` model:
       `server_info`, `tools`, `prompts`, `resources`, `instructions`, `capabilities`.
- `fingerprinter.py`:
  - Adapts `McpFingerprinter` to evaluate all discovered surfaces (tools, prompt descriptions, resource URIs, server instructions) against the vulnerability database and heuristic threat rules.

### 2. CLI Integration
- In `src/mcp_vulnerabilities/cli.py`:
  - Enhance `mcp-vuln probe`:
    ```bash
    mcp-vuln probe --url https://mcp.internal.corp/sse --auth-header "Authorization: Bearer secret-token" --timeout 15
    ```
  - Add flags:
    - `--auth-header <header>`: Injects custom authorization header.
    - `--header <header>`: Injects arbitrary HTTP header (repeatable).
    - `--surfaces {tools,prompts,resources,all}`: Controls which surfaces to query (default: `all`).
    - `--output-format {text,json,sarif}`: Emits comprehensive multi-surface JSON report.

---

## Clear Acceptance Criteria

1. **Unblocked Live Remote Probing**:
   - `mcp-vuln probe --url <url>` connects successfully to live remote or localhost SSE / Streamable HTTP servers without throwing `NotImplementedError`.
2. **Authenticated Endpoint Access**:
   - Authenticated endpoints requiring Bearer tokens or custom API headers accept connections and process JSON-RPC messages cleanly.
3. **Full-Surface Inspection**:
   - Probing an MCP server that advertises `prompts` and `resources` capabilities correctly discovers and indexes prompt templates and resource schemas alongside tools.
4. **Resilience & Timeout Handling**:
   - Gracefully handles unreachable URLs, DNS failures, HTTP 401/403 unauthorized responses, and timeout limits with informative error messages.
5. **Zero External Heavy Dependencies**:
   - Uses Python standard library networking (`urllib.request`, `http.client`) or lightweight requests without adding brittle native binary dependencies.

---

## Comprehensive Test Plan

### A. Unit Tests (`tests/test_probe_transport.py`)
- Test SSE parser with fragmented chunks, multiline data events, and endpoint negotiation.
- Test HTTP header generation and bearer token formatting.
- Test surface capability negotiator when server does not support prompts or resources.

### B. Live Acceptance Tests (Zero Mocks — Real HTTP/SSE Server & Network Sockets)
- `test_live_sse_transport_handshake`: Spin up a real, lightweight HTTP server in a background thread implementing standard MCP SSE protocol (`GET /sse` returning event-stream, `POST /message` receiving JSON-RPC requests). Connect with `HttpSseTransport` over live localhost socket. Complete `initialize`, `notifications/initialized`, and `tools/list` handshake. Verify received tools match actual server definitions.
- `test_live_authenticated_sse_probe`: Configure the live local HTTP/SSE test server to require `Authorization: Bearer test-secret-token-12345` (returning HTTP 401 Unauthorized if missing or invalid). Run `McpProbeClient` with the valid auth header. Verify that the connection succeeds and captures full tool definitions. Run without auth header and verify clean `TransportAuthError` is raised.
- `test_live_full_surface_prompts_and_resources`: Configure the live local test server to expose both `prompts/list` (with a sample prompt template) and `resources/list` (with a sample `file:///` URI). Execute live probe and verify that `DiscoveredMcpSurface` contains tools, prompts, resources, and server instructions.
- `test_live_stdio_real_subprocess`: Probe a real local stdio script without mocking `subprocess.Popen`, verifying that standard I/O pipe communication remains completely intact and backward-compatible.

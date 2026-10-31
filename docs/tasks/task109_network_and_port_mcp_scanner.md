# Task 109: Network & Port MCP Scanner (P0)

**Subsystem:** Network Discovery & Probing (`src/mcp_vulnerabilities/probe/network_scanner.py`, `tests/test_network_scanner.py`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave21_network_inspection_security_picture_and_cli_hub.md](master_plan_wave21_network_inspection_security_picture_and_cli_hub.md)

---

## 1. Objective & Problem Statement

MCP servers are increasingly deployed outside traditional local stdio process pipelines. Remote SSE (Server-Sent Events) and HTTP streaming endpoints run in local Docker containers, Kubernetes sidecars, staging servers, and developer workstations. Many of these services are configured to bind to `0.0.0.0` or open unauthenticated ports on the local network, exposing sensitive system tools, filesystems, database adapters, and internal AI context to any process on the network.

Traditional port scanners (such as Nmap or Masscan) identify open TCP ports, but have no awareness of the Model Context Protocol (MCP) JSON-RPC 2.0 handshake, SSE transport streams, or MCP capability negotiation.

This task implements a high-performance, asynchronous **Network & Port MCP Scanner**:
1. Conducts rapid concurrent TCP socket pre-checks with tight, configurable timeouts (150–300ms, default 200ms) to identify live listeners without blocking.
2. Scans across default MCP ports (`3000, 3001, 3333, 4000, 5000, 5001, 8000, 8001, 8080, 8765, 8800, 9000`), custom lists, or port ranges (e.g. `3000-3010`).
3. Supports flexible target definitions: `localhost`, `127.0.0.1`, IP lists, and CIDR subnets (e.g. `192.168.1.0/24`).
4. Probes candidate endpoints (`/`, `/sse`, `/mcp`, `/v1/mcp`) via JSON-RPC 2.0 `initialize` handshakes, extracting `serverInfo`, `capabilities`, `tools/list`, `prompts/list`, and `resources/list`.

---

## 2. Detailed Technical Requirements

### 2.1 Asynchronous TCP Socket Pre-Check (`src/mcp_vulnerabilities/probe/network_scanner.py`)

1. Implement asynchronous socket pre-checking using `asyncio.open_connection`:
   ```python
   async def check_tcp_port(host: str, port: int, timeout_ms: int = 200) -> bool:
       try:
           _, writer = await asyncio.wait_for(
               asyncio.open_connection(host, port),
               timeout=timeout_ms / 1000.0,
           )
           writer.close()
           await writer.wait_closed()
           return True
       except (asyncio.TimeoutError, OSError):
           return False
   ```
2. Concurrency limiting:
   - Use `asyncio.Semaphore(concurrency)` (default `64`, configurable up to `256`) to prevent operating system file descriptor limits (`EMFILE`) from being exceeded.
3. Port parsing:
   - Implement `parse_port_spec(ports_str: str) -> list[int]`:
     - Parses single ports: `"3000"` -> `[3000]`.
     - Parses comma-delimited ports: `"3000,3001,8000"` -> `[3000, 3001, 8000]`.
     - Parses ranges: `"3000-3005"` -> `[3000, 3001, 3002, 3003, 3004, 3005]`.
     - Validates bounds `1 <= port <= 65535`.
     - Default MCP port preset:
       `DEFAULT_MCP_PORTS = [3000, 3001, 3333, 4000, 5000, 5001, 8000, 8001, 8080, 8765, 8800, 9000]`

### 2.2 Target Specification & CIDR Subnet Expansion

1. Implement `expand_targets(target_spec: str, max_hosts: int = 512) -> list[str]`:
   - Handles `localhost` and `127.0.0.1`.
   - Handles comma-delimited hosts: `"127.0.0.1,10.0.0.5,api.local"`.
   - Handles CIDR notation via `ipaddress.ip_network(target_spec, strict=False)`:
     - Iterates through `network.hosts()`.
     - Enforces safety ceiling: raises `ValueError` if the CIDR block contains more than `max_hosts` (preventing accidental scanning of `/16` or `/8` networks).

### 2.3 JSON-RPC 2.0 Protocol Probing & Handshake

When a TCP port is confirmed open, probe for MCP compatibility:
1. Candidate endpoint paths:
   `CANDIDATE_PATHS = ["/", "/sse", "/mcp", "/v1/mcp"]`
2. HTTP POST JSON-RPC 2.0 Handshake:
   - Send `initialize` payload:
     ```json
     {
       "jsonrpc": "2.0",
       "id": 1,
       "method": "initialize",
       "params": {
         "protocolVersion": "2024-11-05",
         "capabilities": {},
         "clientInfo": {
           "name": "mcp-vuln-scanner",
           "version": "1.21.0"
         }
       }
     }
     ```
   - Headers: `Content-Type: application/json`, `Accept: application/json, text/event-stream`.
   - Valid response check:
     - HTTP 200 with JSON payload containing `"jsonrpc": "2.0"`, `"result": {"protocolVersion": ..., "serverInfo": ..., "capabilities": ...}`.
3. SSE (Server-Sent Events) Probing:
   - If candidate path is `/sse` or response is `text/event-stream`:
     - Connect via HTTP GET with `Accept: text/event-stream`.
     - Read the initial event stream chunk looking for an `endpoint` event containing the POST URI.
     - Post the `initialize` payload to the negotiated endpoint URI.
4. Schema & Capability Introspection:
   - If initialized successfully and `capabilities.get("tools")` is present:
     - Query `tools/list` via JSON-RPC 2.0 to capture tool names, descriptions, and input schemas.
   - If `capabilities.get("prompts")` is present: query `prompts/list`.
   - If `capabilities.get("resources")` is present: query `resources/list`.
   - Record response time (latency in milliseconds).
5. Non-MCP Graceful Handling:
   - If an open port returns 404, standard HTML, or closes connection unexpectedly, classify as non-MCP and terminate probing without raising unhandled exceptions.

### 2.4 Data Models & Reporting

```python
@dataclass
class NetworkMcpEndpoint:
    host: str
    port: int
    path: str
    transport: str  # "http" or "sse"
    server_name: str
    server_version: str
    protocol_version: str
    capabilities: dict[str, Any]
    tools: list[dict[str, Any]]
    prompts: list[dict[str, Any]]
    resources: list[dict[str, Any]]
    response_time_ms: float
    raw_banner: str = ""

@dataclass
class NetworkScanResult:
    targets_probed: list[str]
    ports_scanned: list[int]
    open_ports_count: int
    mcp_endpoints: list[NetworkMcpEndpoint]
    scan_duration_sec: float
```

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_109_1 (Timeout Strictness):** Socket pre-checks against unreachable or filtered IPs strictly terminate within `timeout_ms` (150–300ms) without hanging.
- [ ] **INVARIANT_109_2 (JSON-RPC Handshake Fidelity):** A compliant MCP HTTP/SSE server correctly parses the `initialize` request and returns structured `serverInfo`, `capabilities`, and `tools/list`.
- [ ] **INVARIANT_109_3 (CIDR Expansion Safety):** Passing a CIDR block (e.g. `192.168.1.0/24`) expands valid usable hosts while rejecting networks larger than `max_hosts` (default 512).
- [ ] **INVARIANT_109_4 (Non-MCP Port Resilience):** Standard HTTP web servers (e.g. Nginx, Apache), SSH daemons, or raw sockets returning non-JSON-RPC responses are gracefully filtered without errors.
- [ ] **INVARIANT_109_5 (Resource Cleanup):** All opened sockets, HTTP client sessions, and reader/writer streams are cleanly closed with no unclosed client session warnings.
- [ ] **INVARIANT_109_6 (Test Suite Coverage):** `tests/test_network_scanner.py` provides unit and integration test coverage using a local lightweight mock aiohttp server simulating standard MCP JSON-RPC, SSE transports, and non-MCP HTTP endpoints.

---

## 4. Deliverables

1. `src/mcp_vulnerabilities/probe/network_scanner.py`: Full implementation of asynchronous TCP pre-check, target/CIDR expansion, HTTP/SSE protocol probing, capability introspection, and data models.
2. `tests/test_network_scanner.py`: Mock-backed automated test suite covering socket timeouts, protocol handshakes, SSE streams, CIDR safety bounds, and non-MCP filtering.

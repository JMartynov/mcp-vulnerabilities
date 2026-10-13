# Task 24 Contract: Headless REST API Gateway & Microservice Daemon (mcp-vuln serve)

## Objective
Implement a production-ready, lightweight, headless REST API daemon (`mcp-vuln serve`) that enables enterprise microservice deployments, CI/CD pipeline automation, and external security portals to execute vulnerability scans, server fingerprinting, and client configuration audits over standard HTTP/JSON protocols.

---

## Detailed Technical Architecture & Implementation

### 1. Subsystem Location: `src/mcp_vulnerabilities/api/`
Create package `src/mcp_vulnerabilities/api/` with the following components:
- `server.py`:
  - `McpSecurityApiServer`: Lightweight HTTP daemon using Python's standard library `http.server.ThreadingHTTPServer` or `starlette` / `uvicorn` if installed.
  - Lifecycle management: Clean SIGINT / SIGTERM handlers, graceful shutdown, health probes, and structured JSON access logging.
  - Configurable CLI arguments: `--host` (default `127.0.0.1`), `--port` (default `8080`), `--cors-origins` (optional allowed origins for web dashboards).
- `routes.py`:
  - Request dispatcher routing HTTP methods and paths to controller handlers.
  - Endpoints:
    1. `GET /health` or `GET /api/v1/health`:
       - Returns: `{"status": "ok", "version": "1.0.0", "vulnerabilities_indexed": int, "passports_loaded": int, "uptime_seconds": float}`.
    2. `POST /api/v1/scan/probe`:
       - Request: `{"command": str | null, "url": str | null, "timeout": float, "analyzers": list[str]}`.
       - Connects to target MCP server, captures tools/prompts/resources, runs vulnerability matching and fingerprinting, returns structured findings.
    3. `POST /api/v1/identify`:
       - Request: `{"tools": list[dict]} | {"command": str} | {"url": str}`.
       - Runs Tri-Layer Fingerprint matching against the 5,033+ passport knowledge base, returns detected package identity, repository, confidence %, and matched version.
    4. `POST /api/v1/scan/config`:
       - Request: `{"config": dict, "detect_collisions": bool}`.
       - Parses client configuration dictionary, matches servers against OSV advisories, and detects tool name collisions/shadowing across configured servers.
    5. `GET /api/v1/vulnerabilities`:
       - Query params: `cve`, `tool`, `ecosystem`, `limit`, `offset`.
       - Returns paginated list of OSV 1.6 vulnerability records matching search criteria.
- `middleware.py`:
  - CORS header handling, request ID injection (`X-Request-ID`), error response formatting with standardized JSON error schemas (`{"error": {"code": str, "message": str, "details": any}}`).
- `openapi.py`:
  - Generates OpenAPI 3.0 specification dynamically available at `GET /openapi.json` and interactive Swagger/Scalar documentation at `GET /docs`.

### 2. CLI Integration
- In `src/mcp_vulnerabilities/cli.py`:
  - Add subcommand `serve`:
    ```bash
    mcp-vuln serve --host 0.0.0.0 --port 8080
    ```
  - Support environment variable configuration: `MCP_VULN_PORT`, `MCP_VULN_HOST`, `MCP_VULN_LOG_LEVEL`.

---

## Clear Acceptance Criteria

1. **Production Daemon Lifecycle**:
   - Starts bound to specified host/port, handles concurrent HTTP requests without blocking, and terminates cleanly upon receiving SIGTERM.
2. **Standardized REST Endpoints**:
   - All specified endpoints (`/health`, `/scan/probe`, `/identify`, `/scan/config`, `/vulnerabilities`) respond with correct HTTP status codes (200, 400, 404, 500) and conform strictly to JSON schemas.
3. **OpenAPI Specification**:
   - Exposes valid OpenAPI 3.0 schema at `/openapi.json` enabling turn-key client generation for enterprise security platforms.
4. **Collision and Fingerprint Parity**:
   - REST responses for `/identify` and `/scan/config` produce identical analytical results to the CLI equivalents.
5. **Zero Required Heavyweight Frameworks**:
   - Operates with zero extra dependencies using built-in standard library networking while remaining compatible with ASGI/FastAPI environments.

---

## Comprehensive Test Plan

### A. Unit Tests (`tests/test_api_server.py`)
- Test routing and request dispatch logic.
- Test JSON validation and standardized error response formatting.
- Test OpenAPI JSON schema generator compliance.

### B. Live Acceptance Tests (Zero Mocks — Real HTTP Sockets & Network Loopback)
- `test_live_server_lifecycle_and_health`: Launch the live HTTP server in a background thread on a dynamic free localhost port. Make a real HTTP GET request using `urllib.request.urlopen("http://127.0.0.1:<port>/health")`. Validate 200 OK, JSON content-type, and accurate counts of indexed vulnerabilities and passports.
- `test_live_api_identify_endpoint`: Send a real HTTP POST request containing live tool signatures extracted from `data/passports.json.gz`. Verify the server returns 200 OK with detected package identity and confidence score >= 0.95.
- `test_live_api_scan_config_with_collisions`: Send a real HTTP POST request with a multi-server client config containing colliding tool definitions. Verify the server returns 200 OK with collision warnings and affected package names.
- `test_live_api_vulnerabilities_query`: Query `/api/v1/vulnerabilities?tool=read_file&limit=5` over live HTTP and verify returned JSON array matches on-disk OSV records.

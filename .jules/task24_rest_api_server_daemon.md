# Task 24 Contract: REST API Server Mode (mcp-vuln serve)

## Objective
Implement a lightweight REST API daemon matching and superseding Cisco's `mcp-scanner-api`. Enable enterprise microservice deployments, remote security scanning pipelines, and web UI backends to query vulnerability records, identify MCP servers, and audit configurations over HTTP.

---

## Architectural Specification

### 1. New Subsystem: `src/mcp_vulnerabilities/api/`
Create package `src/mcp_vulnerabilities/api/` containing:
- `server.py`:
  - Provides a lightweight HTTP REST server using standard library `http.server` or `starlette` / `fastapi` (with graceful standard library fallback).
  - Endpoints:
    - `GET /health`: Returns service health, total indexed vulnerabilities count, total loaded passports count.
    - `POST /api/v1/scan/probe`: Accepts JSON `{"command": str, "url": str, "analyzers": list[str]}` and returns runtime probe and threat findings.
    - `POST /api/v1/identify`: Accepts JSON `{"tools": list[dict]}` or `{"command": str}` and returns matched server identity from the 5,033+ passports knowledge base.
    - `POST /api/v1/scan/config`: Accepts client config JSON and returns vulnerability audit + tool collision reports.
    - `GET /api/v1/vulnerabilities`: Supports query parameters `cve`, `tool`, `ecosystem`, `limit`, returning OSV 1.6 records.
- `router.py`:
  - Request routing, JSON serialization, and error handling.

---

### 2. CLI Integration
- Add subcommand `mcp-vuln serve`:
  - Arguments:
    - `--host`: Host to bind (default `0.0.0.0` or `127.0.0.1`).
    - `--port`: Port number (default `8080`).
  - Launches server with access logging and graceful SIGINT/SIGTERM shutdown.

---

### 3. Verification & Acceptance Criteria
- Unit tests in `tests/test_api_server.py`:
  1. `test_api_health_endpoint`: Tests `/health`.
  2. `test_api_identify_endpoint`: Tests `/api/v1/identify` with mock tools payload.
  3. `test_api_vulnerabilities_search`: Tests `/api/v1/vulnerabilities?tool=...`.
  4. `test_api_scan_config`: Tests `/api/v1/scan/config` with collision detection.
- Non-Interactive Completion Directive: Complete autonomously without asking follow-up questions so session cleanly transitions to `Completed`.

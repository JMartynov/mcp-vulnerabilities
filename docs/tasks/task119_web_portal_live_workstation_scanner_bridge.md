# Task 119: Web Portal Live Workstation Scanner Bridge (P0)

**Subsystem:** Localhost Web Bridge Daemon & Browser Integration (`src/mcp_vulnerabilities/daemon/bridge.py`, `docs/index.html`, `docs/app.js`, `tests/daemon/test_bridge.py`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave22_daemon_sandbox_tui_and_web_bridge.md](master_plan_wave22_daemon_sandbox_tui_and_web_bridge.md)

---

## 1. Objective & Problem Statement

The `mcp-vulnerabilities` static web portal (`docs/index.html`) hosted on GitHub Pages provides an interactive client-side audit dropzone where users can drag and drop configuration files (`claude_desktop_config.json`, `cursor_config.json`, etc.) to inspect them for known CVEs.

However, requiring users to manually navigate hidden system directories (`~/Library/Application Support/Claude/...`, `~/.cursor/...`), copy files, or paste raw JSON introduces significant friction. Many developers have 5 to 15 different AI clients configured simultaneously and do not know where all configuration files reside.

To bridge this gap while preserving zero-cloud data privacy, this task introduces a secure, local-only **Web Portal Live Workstation Scanner Bridge**:
1. Implements a lightweight, local loopback HTTP and WebSocket bridge daemon: `mcp-vuln bridge --port 8765`.
2. Connects the browser web portal to the developer's local machine over strictly validated loopback CORS (`http://127.0.0.1:8765`).
3. Embeds a live "Audit My Machine (Live Bridge)" interface into the portal's audit tab, automatically discovering local AI client installations and scanning network listeners.
4. Streams real-time baseline drift comparisons and security telemetry directly into the browser DOM.
5. Enables 1-click auto-fix remediation directly from the browser UI, writing safe version updates locally via authenticated bridge requests.
6. Enforces ironclad origin validation, anti-CSRF token handshakes, and loopback binding (`127.0.0.1` only) so malicious external websites can never access the bridge.

---

## 2. Detailed Technical Requirements

### 2.1 Local Bridge Daemon (`src/mcp_vulnerabilities/daemon/bridge.py`)

1. **Loopback Server Architecture**:
   - Implemented using Python's standard `http.server` or lightweight `asyncio` HTTP/WebSocket server.
   - Binds strictly to `127.0.0.1` (IPv4) and `::1` (IPv6). Explicitly rejects binding to `0.0.0.0` or external network adapters.
   - Default port: `8765` (configurable via `--port`).
2. **Origin & CSRF Security Controls**:
   - **Allowed Origins**: Strictly validates the HTTP `Origin` header against an allowlist:
     - `https://jmartynov.github.io` (production GitHub Pages portal)
     - `http://localhost:*`, `http://127.0.0.1:*` (local development servers)
     - Rejects any requests from arbitrary third-party web origins with `403 Forbidden`.
   - **CORS Headers**:
     - `Access-Control-Allow-Origin`: Dynamically set to validated allowed origin.
     - `Access-Control-Allow-Methods`: `GET, POST, OPTIONS`.
     - `Access-Control-Allow-Headers`: `Content-Type, X-MCP-Bridge-Token`.
   - **Ephemeral Session Token Handshake**:
     - Upon startup, the daemon generates a cryptographically secure random session token (`secrets.token_hex(16)`).
     - The daemon displays this token in the terminal: `Bridge token: <token>`.
     - Initial browser connection requests `/api/v1/auth/challenge` to establish a local handshake session cookie or header (`X-MCP-Bridge-Token`), preventing cross-site port scanning or unauthorized invocations.
3. **REST & WebSocket Endpoints**:
   - `GET /health`:
     - Returns JSON: `{"status": "ok", "version": "1.22.0", "clients_detected": 14, "os": "darwin"}`.
   - `GET /api/v1/scan`:
     - Executes `UniversalClientConfigScanner.scan_all_clients()` and returns sanitized client server configurations (with all secret tokens masked as `***REDACTED***`).
   - `GET /api/v1/drift`:
     - Compares live workstation inventory against `~/.mcp-vuln/state/security_picture.json` baseline.
     - Returns categorized drift findings (`new_vulnerabilities`, `resolved_vulnerabilities`, `shadow_servers`, `tamper_events`).
   - `POST /api/v1/fix`:
     - Body: `{"client": "cursor", "server_name": "git-server", "target_version": "1.1.2"}`.
     - Invokes `ClientConfigFixer` to update the local configuration file safely.
   - `GET /ws/live` (WebSocket):
     - Bi-directional event stream broadcasting real-time progress while running extensive port scans (e.g. `{"event": "port_probed", "port": 8000, "status": "open"}`).

### 2.2 Web Portal Frontend Integration (`docs/index.html`, `docs/app.js`)

1. **UI Components (`docs/index.html`)**:
   - Inside `<section id="audit-view">`, add a dedicated Live Bridge Controller:
     ```html
     <div id="live-bridge-container" class="live-bridge-panel">
       <div class="bridge-status-bar">
         <span id="bridge-status-pill" class="status-pill disconnected">⚪ Bridge Disconnected</span>
         <span id="bridge-info-text">Run <code>mcp-vuln bridge</code> in your terminal to enable 1-click live scanning</span>
       </div>
       <div id="bridge-actions" class="bridge-actions-row" style="display: none;">
         <button id="btn-live-scan" class="btn-primary">⚡ Scan My Live Workstation</button>
         <button id="btn-live-drift" class="btn-secondary">📸 Check Baseline Drift</button>
       </div>
       <div id="bridge-results-container" class="bridge-results-area"></div>
     </div>
     ```
2. **Frontend Controller Logic (`docs/app.js`)**:
   - Auto-Discovery Poller:
     - On page load, `checkBridgeConnection()` sends a ping to `http://127.0.0.1:8765/health`.
     - If responsive:
       - Updates `#bridge-status-pill` to `🟢 Local Bridge Connected (v1.22.0)`.
       - Reveals live scan and drift action buttons.
     - If unreachable: displays helpful terminal command instructions to start the bridge.
   - Live Audit Action:
     - Clicking `#btn-live-scan` queries `GET /api/v1/scan`.
     - Populates the existing audit results view with all discovered servers across local AI clients.
     - Highlights vulnerable servers with badges, CVSS scores, and safe upgrade targets.
     - Renders an interactive `[🛠️ Auto-Fix in Client]` button next to each vulnerable server, triggering `POST /api/v1/fix`.
   - Drift Comparison Modal / Drawer:
     - Clicking `#btn-live-drift` fetches `GET /api/v1/drift` and renders visual diff cards showing newly introduced vulnerabilities or newly opened shadow ports.

### 2.3 CLI Command Specification (`src/mcp_vulnerabilities/cli.py`)

```text
mcp-vuln bridge [OPTIONS]

Options:
  --port PORT             Loopback port to listen on (default: 8765).
  --allowed-origin ORIGIN Additional CORS allowed origin URL.
  --no-auth               Disable session token requirement (for local testing).
  --open-browser          Automatically open docs/index.html in default browser on launch.
```

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_119_1 (Strict Loopback Binding):** The bridge daemon strictly binds to loopback interface `127.0.0.1` and never opens external interfaces (`0.0.0.0`).
- [ ] **INVARIANT_119_2 (CORS Origin Enforcement):** HTTP requests originating from unapproved domains (e.g. `evil.com`) are rejected with `403 Forbidden` and zero response data.
- [ ] **INVARIANT_119_3 (Secret Redaction Invariant):** All client configuration payloads transmitted across the bridge have tokens, passwords, and sensitive keys redacted (`***REDACTED***`).
- [ ] **INVARIANT_119_4 (1-Click Safe Remediation):** Invoking `POST /api/v1/fix` validates target parameters, upgrades the client config file, and returns HTTP 200 with diff confirmation.
- [ ] **INVARIANT_119_5 (Graceful Disconnected Degradation):** When the bridge daemon is not running, the web portal maintains 100% functionality for manual JSON drag-and-drop auditing without JavaScript console errors.
- [ ] **INVARIANT_119_6 (Test Suite Coverage):** `tests/daemon/test_bridge.py` verifies loopback socket binding, CORS header validation, challenge token authentication, and API endpoints using mock client configurations.

---

## 4. Deliverables

1. `src/mcp_vulnerabilities/daemon/bridge.py`: Localhost HTTP/WebSocket bridge server with origin validation, token handshake, client scan aggregation, drift reporting, and remediation endpoints.
2. `docs/index.html`: Added Live Bridge panel, connection status indicator, and action controls in `#audit-view`.
3. `docs/app.js`: Bridge connectivity check, 1-click live scan caller, drift comparison viewer, and auto-fix API integration.
4. `src/mcp_vulnerabilities/cli.py`: Subcommand registration for `mcp-vuln bridge`.
5. `tests/daemon/test_bridge.py`: Automated test suite covering loopback security, CORS filtering, endpoint contracts, and fix handler execution.

# Task 163: Frontend Web Portal Live Bridge Client Integration

## Objective
Wire the frontend Web Portal (`docs/index.html` and `docs/app.js`) to the local daemon bridge (`src/mcp_vulnerabilities/daemon/bridge.py`), fixing dead connection checks, attaching action listeners, and providing live streaming feedback via SSE/WebSocket.

## Background & Issues Identified
- `checkBridgeConnection()` in `docs/app.js` is defined but never invoked on initial page load or when switching to the Audit tab.
- `#btn-live-scan` and `#btn-live-drift` in `docs/index.html` have no click event listeners attached.
- `runLiveScan()` does a blocking fetch instead of using `EventSource('/api/v1/events')` or `WebSocket('ws://127.0.0.1:8765/ws/live')` for live stepped progress (`discovering_clients`, `probing_ports`, `analyzing_drift`, `done`).
- `tests/daemon/test_bridge_stream.py` needs complete assertions for event streaming.

## Scope of Changes
1. `docs/app.js`:
   - Invoke `checkBridgeConnection()` during app initialization and when the "Audit / Machine Posture" tab is selected.
   - Bind click events for `#btn-live-scan` and `#btn-live-drift`.
   - Update `runLiveScan()` to stream events via `EventSource('/api/v1/events')` (with fallback to REST `/api/v1/scan`), updating progress percentages and step labels.
2. `docs/index.html`:
   - Add `#bridge-progress-bar` and step status indicators in `#bridge-results-container`.
3. `tests/daemon/test_bridge_stream.py`:
   - Verify SSE event formatting and subscriber dispatch under simulation mode.

## Acceptance Criteria
- Web Portal displays "Local Daemon Connected" status badge when bridge is active on `127.0.0.1:8765`.
- Clicking "Scan Local Workstation" streams live progress steps into `#bridge-progress-bar`.
- `pytest tests/daemon/test_bridge_stream.py` passes 100%.

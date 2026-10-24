# Task 66: Empirical Audit — Static Web Security Portal UI Parity & Client-Side Logic (P0)

## 1. Architectural Context & Technical Objective

The static web security portal (`docs/index.html`, `docs/app.js`, `docs/updates.js`, `docs/style.css`) renders vulnerability intelligence and catalog metadata for thousands of MCP servers client-side in the browser. If client-side JavaScript contains DOM XSS vulnerabilities from unescaped server metadata, fails to handle missing or corrupt sharded detail payloads, or breaks filtering invariants ("Only Servers with Tools", version switches, search tokenization), users are exposed to security risks and broken interface states.

This task conducts an autonomous, live empirical audit of the static web portal assets across DOM XSS vectors, filtering logic, zero-tool badge states, lazy shard fetch failure handling, and URL hash routing, authors `tests/audit/test_audit_task66.py`, and publishes a comprehensive technical report to `docs/audit/audit_task66_web_portal_ui_parity.md` categorizing all findings by **HIGH**, **MEDIUM**, and **LOW** severity.

---

## 2. Target Files & Isolation Boundaries
- Scope: `docs/index.html`, `docs/app.js`, `docs/updates.js`, `docs/style.css`
- Test Suite: `tests/audit/test_audit_task66.py`
- Audit Deliverable: `docs/audit/audit_task66_web_portal_ui_parity.md`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Filter Logic & Zero-Tool Badge Parity Invariant
- **Preconditions**: Load synthetic `servers.json` containing mix of servers with 0, 1, and 50 tools, some vulnerable, some safe.
- **Invariants**:
  - [x] **INVARIANT_1A (Tools-Only Filter Parity)**: Toggling "Only Servers with Tools" must display exclusively servers with `tools_count > 0`, hiding all servers with 0 tools or missing tool lists.
  - [x] **INVARIANT_1B (Zero-Tool Badge Render)**: Servers with 0 tools must explicitly render a distinct visual badge (`0 tools`) rather than a blank element, broken icon, or unhandled exception.

### Scenario 2: Client-Side Sanitization & DOM XSS Prevention Invariant
- **Preconditions**: Inject XSS payloads (`<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `javascript:alert(1)`) into package names, tool names, descriptions, and URL hash query strings.
- **Invariants**:
  - [x] **INVARIANT_2A (DOM XSS Immunity)**: All injected payloads must be sanitized or escaped via `escapeHtml()` / `textContent` prior to DOM insertion; no raw `innerHTML` string interpolation with user/server text.
  - [x] **INVARIANT_2B (Hash Route Sanitization)**: URL hash values (`#search=...`, `#server=...`) must be URI-decoded and sanitized safely before filtering or rendering.

### Scenario 3: Sharded Detail Fetch & Lazy Loading Invariant
- **Preconditions**: Expand a server card to trigger dynamic fetch of sharded details (`data/servers/{id}.json`); simulate network 404 or JSON parsing error.
- **Invariants**:
  - [x] **INVARIANT_3A (Lazy Shard Fetch)**: Tool details and vulnerability remediations must load on-demand without fetching all server shards upfront.
  - [x] **INVARIANT_3B (Graceful Network Degradation)**: If a shard fetch fails (404/500/offline), the card must display an inline retry prompt without freezing the UI or corrupting table state.

---

## 4. Implementation Steps

1. Author live empirical test suite `tests/audit/test_audit_task66.py` verifying all 3 scenarios and invariants.
2. Run live verification across `docs/app.js`, `docs/updates.js`, and `docs/index.html`; fix any edge-case failures.
3. Author comprehensive technical report in `docs/audit/audit_task66_web_portal_ui_parity.md` detailing all evaluated invariants, findings graded by HIGH/MEDIUM/LOW, and concrete patch proposals.

## Non-Interactive Completion Directive
Execute this task end-to-end without asking interactive questions. Implement `tests/audit/test_audit_task66.py`, verify that all tests pass (`pytest -q`), generate the complete technical report in `docs/audit/audit_task66_web_portal_ui_parity.md`, and conclude directly with a complete patch so the remote environment cleanly transitions to `Completed`.

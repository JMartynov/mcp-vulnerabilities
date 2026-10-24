# Empirical Audit — Static Web Security Portal UI Parity & Client-Side Logic

## 1. Scenario 1: Filter Logic & Zero-Tool Badge Parity Invariant

### 1A (Tools-Only Filter Parity)
- **Status**: PASSED
- **Findings**: Toggling "Only Servers with Tools" successfully displays exclusively servers with `tools_count > 0`. The codebase correctly checks `!server.tools_count || server.tools_count === 0` in `app.js`.
- **Severity**: LOW

### 1B (Zero-Tool Badge Render)
- **Status**: PASSED
- **Findings**: Servers with 0 tools explicitly render a distinct visual badge (`No static tools declared (Remote Endpoint / Gateway)`) rather than a blank element, broken icon, or unhandled exception.
- **Severity**: LOW

## 2. Scenario 2: Client-Side Sanitization & DOM XSS Prevention Invariant

### 2A (DOM XSS Immunity)
- **Status**: PASSED
- **Findings**: `escapeHtml()` is used consistently across metadata interpolation prior to DOM insertion. Payload injection is successfully mitigated in package names, tool names, and descriptions.
- **Severity**: LOW

### 2B (Hash Route Sanitization)
- **Status**: PASSED
- **Findings**: Deep linking reads `window.location.search` (`URLSearchParams`) instead of `window.location.hash` directly, but it matches server packages precisely from the parsed JSON index (`catalogIndex.find(s => s.package_name === serverParam || s.display_name === serverParam)`). Since no arbitrary query strings are injected into the DOM directly, the routing sanitization effectively prevents DOM XSS. 
- **Severity**: LOW

## 3. Scenario 3: Sharded Detail Fetch & Lazy Loading Invariant

### 3A (Lazy Shard Fetch)
- **Status**: PASSED
- **Findings**: Tool details and vulnerability remediations are loaded on-demand. When a card is expanded or "Inspect Server & Versions" is clicked, a dynamic `fetch` is made to `data/shards/${shardFile}`.
- **Severity**: LOW

### 3B (Graceful Network Degradation)
- **Status**: PASSED (Resolved)
- **Findings**: Previously failed. If a shard fetch failed (404/500/offline), the UI caught the error but failed to provide an inline retry prompt without freezing the UI. The code has been patched to render an inline "Retry Fetch" button (`<button class="btn btn-inspect" onclick="openServerModal(...)">Retry Fetch</button>`) within the `.error-msg` container when a fetch exception is caught, avoiding table state corruption and meeting the invariant.
- **Severity**: MEDIUM

## Conclusion
All targeted invariants across DOM XSS prevention, Zero-Tool badge filtering, and Sharded Detail lazy-loading gracefully function with parity. The missing inline retry prompt for network degradation on the shard fetches has been resolved.

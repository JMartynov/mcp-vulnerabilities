# Task Contract: Task 103 — Progressive Web App (PWA) Offline Service Worker (P1)

### 1. Context & Objective:
Implement Progressive Web App (PWA) offline capabilities for the static security portal:
- Provide W3C Web App Manifest (`docs/manifest.json`) for standalone desktop/mobile installation.
- Implement Service Worker (`docs/sw.js`) with Cache-First strategy for core static shell assets (`.`, `index.html`, `updates.html`, `analytics.html`, `style.css`, `app.js`, `updates.js`, `analytics.js`, `favicon.svg`, `manifest.json`), Stale-While-Revalidate for `mcp_catalog_index.json` and `analytics.json`, and on-demand Cache-First for shard files (`shards/*.json`).
- Link `manifest.json` and register the service worker in `docs/index.html`, `docs/updates.html`, and `docs/analytics.html`.

### 2. Files to Create or Modify:
- Create `docs/manifest.json`
- Create `docs/sw.js`
- Modify `docs/index.html` (link manifest, register SW)
- Modify `docs/updates.html` (link manifest, register SW)
- Modify `docs/analytics.html` (link manifest, register SW)
- Hook in `docs/app.js`, `docs/updates.js`, and `docs/analytics.js` if registering via JS:
  ```javascript
  if ("serviceWorker" in navigator && (window.location.protocol === "https:" || window.location.hostname === "localhost")) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("./sw.js").then((reg) => {
        console.debug("[SW] Registered with scope:", reg.scope);
      }).catch((err) => {
        console.warn("[SW] Registration failed:", err);
      });
    });
  }
  ```

### 3. Strict Guardrails:
- Zero Unauthorized Dependencies: Standard browser Web APIs and valid JSON only.
- Ensure `CACHE_NAME = "mcp-vuln-cache-v1"`. In `activate` event, clean up any outdated `mcp-vuln-cache-*` caches and call `self.clients.claim()`.
- In `install` event, call `self.skipWaiting()`.
- Validate syntax with `node -c docs/sw.js`, `node -c docs/app.js`, `node -c docs/updates.js`, `node -c docs/analytics.js`.

### 4. Defaults when blocked:
- If a rule above cannot be met, leave that part as it was, list it in the summary with the reason, and continue. Do not ask questions.

### 5. Completion Directive:
- Implement all requested changes, verify JavaScript syntax, and finalize your response directly with a concise summary. Do not ask conversational follow-up questions, so the task cleanly transitions to Completed.

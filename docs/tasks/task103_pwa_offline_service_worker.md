# Task 103: Progressive Web App (PWA) Offline Service Worker (P1)

**Subsystem:** Web App Infrastructure (`docs/manifest.json`, `docs/sw.js`, `docs/index.html`, `docs/updates.html`, `docs/analytics.html`)  
**Priority:** `P1`  
**Parent Plan:** [master_plan_wave20_mcp_fingerprints_capability_adoption.md](master_plan_wave20_mcp_fingerprints_capability_adoption.md)

---

## 1. Objective & Problem Statement

Security engineers and developers frequently audit local environments, air-gapped workstations, or conference environments where internet connectivity is unstable or restricted. Currently, refreshing or opening `docs/index.html`, `docs/updates.html`, or `docs/analytics.html` without active network connectivity results in blank screens or browser network failure errors.

This task transforms the static security portal into a **Progressive Web App (PWA)**:
1. Provides a standard W3C Web App Manifest (`docs/manifest.json`) supporting standalone desktop/mobile installation.
2. Implements a high-efficiency Service Worker (`docs/sw.js`) utilizing a **Cache-First** strategy for core static assets (HTML/CSS/JS/icons) and a **Stale-While-Revalidate / Cache-First** strategy for catalog index files and loaded shards.
3. Registers the service worker across all three public portal pages (`index.html`, `updates.html`, `analytics.html`).

---

## 2. Detailed Technical Requirements

### 2.1 Web App Manifest (`docs/manifest.json`)
1. Create `docs/manifest.json` conforming to W3C Web App Manifest specifications:
   ```json
   {
     "name": "MCP Security Vulnerability Database & Explorer",
     "short_name": "MCP Vuln",
     "description": "Cryptographic fingerprinting, OSV vulnerability intelligence, and multi-client configuration hub for Model Context Protocol servers.",
     "start_url": "./index.html",
     "scope": "./",
     "display": "standalone",
     "background_color": "#0f172a",
     "theme_color": "#0f172a",
     "orientation": "any",
     "icons": [
       {
         "src": "favicon.svg",
         "sizes": "any",
         "type": "image/svg+xml",
         "purpose": "any maskable"
       }
     ],
     "categories": ["security", "developer-tools", "productivity"]
   }
   ```
2. In `docs/index.html`, `docs/updates.html`, and `docs/analytics.html`, link the manifest inside `<head>`:
   ```html
   <link rel="manifest" href="manifest.json">
   <meta name="theme-color" content="#0f172a">
   <meta name="apple-mobile-web-app-capable" content="yes">
   <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
   ```

### 2.2 Service Worker Implementation (`docs/sw.js`)
1. Define versioned cache constant:
   ```javascript
   const CACHE_NAME = "mcp-vuln-cache-v1";
   const STATIC_ASSETS = [
     "./",
     "./index.html",
     "./updates.html",
     "./analytics.html",
     "./style.css",
     "./app.js",
     "./updates.js",
     "./analytics.js",
     "./favicon.svg",
     "./manifest.json"
   ];
   ```
2. Lifecycle Events:
   - `install`: Pre-cache all items in `STATIC_ASSETS`. Call `self.skipWaiting()`.
   - `activate`: Iterate through caches; delete any cache matching `mcp-vuln-cache-*` that does not match current `CACHE_NAME`. Call `self.clients.claim()`.
3. Fetch Routing Strategy:
   - **Static Shell Assets**: If request URL matches static assets or ends in `.css`, `.js`, `.svg`, `.html`:
     * Respond with Cache-First; if cache miss, fetch from network and store in cache.
   - **Catalog Index & Analytics Data** (`mcp_catalog_index.json`, `analytics.json`):
     * Stale-While-Revalidate: Return cached version immediately if present for instant rendering, while dispatching background network fetch to refresh cache.
   - **Shard Files** (`shards/*.json`):
     * Cache-First on demand: When the user inspects a server, cache the loaded shard. Next time the user inspects any server in that shard, serve directly from cache offline.
   - **External Requests / CDNs**: Bypass service worker or use network-first with cache fallback.

### 2.3 Portal Registration Hooks
1. At the end of `docs/app.js`, `docs/updates.js`, and `docs/analytics.js` (or inline in `<head>`):
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

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_103_1 (Valid W3C Manifest):** `docs/manifest.json` is syntactically valid JSON and meets Chrome Lighthouse PWA installability requirements.
- [ ] **INVARIANT_103_2 (Offline Shell Availability):** Navigating to `index.html`, `updates.html`, or `analytics.html` in Chrome DevTools Offline mode loads the complete shell, CSS, and interactive UI without connection errors.
- [ ] **INVARIANT_103_3 (Offline Shard Caching):** Inspecting a server while online caches its shard; inspecting the same server (or another in the same shard) offline renders full version timelines and toolsets.
- [ ] **INVARIANT_103_4 (Cache Invalidation on Version Bump):** Updating `CACHE_NAME` in `sw.js` purges stale caches on activation without requiring manual browser cache clearing.
- [ ] **INVARIANT_103_5 (Syntax Cleanliness):** `node -c docs/sw.js` passes with zero errors.

---

## 4. Deliverables

1. `docs/manifest.json`: Web app manifest configuration with icons, theme colors, and metadata.
2. `docs/sw.js`: Service worker implementation with Cache-First, Stale-While-Revalidate, and shard caching.
3. `docs/index.html`, `docs/updates.html`, `docs/analytics.html`: Manifest `<link>` tags and service worker registration scripts.

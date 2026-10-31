# Task 101: Multi-Server Safe Config Basket & Floating Bottom Drawer (P0)

**Subsystem:** Configuration Hub (`docs/index.html`, `docs/updates.html`, `docs/app.js`, `docs/updates.js`, `docs/style.css`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave20_mcp_fingerprints_capability_adoption.md](master_plan_wave20_mcp_fingerprints_capability_adoption.md)

---

## 1. Objective & Problem Statement

Currently, developers wishing to set up an MCP client environment (e.g., Claude Desktop, Cursor, Cline, Zed, Windsurf, or Docker) must inspect servers one by one, manually extract package names, lookup safe remediation versions, and stitch together JSON configurations by hand. This tedious process invites version pinning errors, missing environment variables, and deployment of vulnerable releases.

This task introduces an interactive **Multi-Server Safe Configuration Basket**:
1. Checkboxes on every server card across both the main directory and the recent updates portal.
2. A sliding, floating bottom drawer (`#bottomDrawer`) tracking selected servers in real time.
3. A multi-client unified configuration modal (`#configModal`) generating complete, drop-in configurations for 6 major AI clients, with every server pinned strictly to its `recommended_safe_version`.
4. 1-click actions: "Copy Combined Config" and "Download config.json".

---

## 2. Detailed Technical Requirements

### 2.1 Server Card Checkbox & Selection State (`docs/app.js` & `docs/updates.js`)
1. Maintain global basket state:
   ```javascript
   const configBasket = new Map(); // package_name -> serverObject
   ```
2. In `renderDirectoryCards()` (`docs/app.js`) and `renderUpdateCards()` (`docs/updates.js`), inject a selection checkbox into `.server-card-header`:
   ```html
   <label class="card-select-label" title="Select for multi-server configuration">
     <input type="checkbox" class="server-checkbox" data-pkg="${escapeHtml(s.package_name)}" ${configBasket.has(s.package_name) ? "checked" : ""}>
     <span class="checkbox-custom"></span>
   </label>
   ```
3. When checked:
   - Add server record to `configBasket`.
   - Add `.selected` class to parent `.server-card`.
   - Update floating drawer badge and visibility.
4. When unchecked:
   - Remove from `configBasket`.
   - Remove `.selected` class.
   - If basket becomes empty, slide down and hide bottom drawer.
5. Selection state must persist across infinite scroll batch additions and search filter changes.

### 2.2 Sliding Floating Bottom Drawer (`#bottomDrawer`) (`docs/index.html` & `docs/updates.html`)
1. In both `docs/index.html` and `docs/updates.html`, add markup before closing `</body>`:
   ```html
   <aside id="bottomDrawer" class="floating-drawer" aria-label="Configuration Basket" hidden>
     <div class="drawer-content">
       <div class="drawer-info">
         <span class="drawer-badge" id="drawerSelectedCount">0</span>
         <span class="drawer-text">MCP Servers Selected</span>
         <div class="drawer-pills" id="drawerPillsContainer"></div>
       </div>
       <div class="drawer-actions">
         <button type="button" class="btn btn-outline btn-sm" id="drawerClearBtn">Clear All</button>
         <button type="button" class="btn btn-primary btn-sm" id="drawerConfigureBtn">
           ⚡ Generate Safe Config (<span id="drawerActionCount">0</span>)
         </button>
       </div>
     </div>
   </aside>
   ```
2. Drawer behavior:
   - When `configBasket.size > 0`, remove `hidden` attribute and apply `.drawer-open` CSS class (smooth translateY transition).
   - Render mini pill tags for the selected servers in `#drawerPillsContainer` with `✕` remove buttons.
   - "Clear All" clears `configBasket`, unchecks all visible checkboxes, and hides the drawer.
   - Clicking "Generate Safe Config" opens `#configModal`.

### 2.3 Multi-Client Configuration Modal (`#configModal`)
1. In `docs/index.html` and `docs/updates.html`, add `<dialog id="configModal" class="modal-dialog modal-large">`:
   - Header with title: "Combined Safe Client Configuration" and close button.
   - Collision Warning Container: `<div id="configCollisionBanner" class="alert-banner" style="display:none;"></div>` (wired in Task 102).
   - Client Selector Tabs (6 target environments):
     - `Claude Desktop` (`claude_desktop_config.json`)
     - `Cursor` (`.cursor/mcp.json`)
     - `Cline` (`cline_mcp_settings.json`)
     - `Zed` (`settings.json` -> `context_servers`)
     - `Windsurf` (`mcp_config.json`)
     - `Docker Compose` (`docker-compose.yml`)
   - Pre-formatted code block: `<pre><code id="combinedConfigCode"></code></pre>`.
   - Action buttons:
     - `[ 📋 Copy Combined Config ]` with visual tooltip feedback.
     - `[ 💾 Download config.json ]` generating dynamic file download via `URL.createObjectURL(new Blob(...))`.
2. Configuration Generator Engine:
   - For each server in `configBasket`:
     - Determine target version: strictly use `recommended_safe_version` if present; fallback to clean latest release; never export known vulnerable version tags.
     - Format command and arguments based on ecosystem:
       * `npm`: command `npx`, args `["-y", `${package_name}@${safe_version}`]`
       * `pypi`: command `uvx`, args `[`--from`, `${package_name}==${safe_version}`, command_bin]`
       * `docker`: image tag `image:${safe_version}`
     - Extract `required_env_vars` and inject placeholder keys into `"env": { "KEY": "YOUR_KEY_HERE" }`.
   - Format correctly according to each client's schema:
     - Claude / Cursor / Windsurf: `{"mcpServers": { "<server_key>": { "command": "...", "args": [...], "env": {...} } } }`
     - Cline: `{"mcpSettings": { "mcpServers": { ... } } }`
     - Zed: `{"context_servers": { "<server_key>": { "command": { "path": "...", "args": [...] }, "settings": {} } } }`
     - Docker: compose YAML service definitions with healthchecks and network bridges.

### 2.4 Styling & Transitions (`docs/style.css`)
1. Style `.floating-drawer`:
   - Position: `fixed`, `bottom: 0`, `left: 0`, `right: 0`, `z-index: 1000`.
   - Backdrop: blurred dark glassmorphism (`background: rgba(15, 23, 42, 0.95); backdrop-filter: blur(12px)`).
   - Box shadow: `0 -4px 20px rgba(0, 0, 0, 0.4)`.
   - Transition: `transform 0.25s cubic-bezier(0.16, 1, 0.3, 1)`.
2. Style `.server-card.selected`:
   - Distinct highlight border (`border-color: var(--primary); box-shadow: 0 0 12px rgba(56, 189, 248, 0.2)`).

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_101_1 (Cross-Batch Selection Persistence):** Checking a card, scrolling to load new batches (from Task 100), and scrolling back retains the card's checked state and visual `.selected` highlight.
- [ ] **INVARIANT_101_2 (Safe Version Pinning Invariant):** If package `example-pkg` has vulnerabilities up to `v1.2.0` and `recommended_safe_version: "1.2.1"`, the exported config must pin `@example-pkg@1.2.1` and NEVER `@latest` or `@1.2.0`.
- [ ] **INVARIANT_101_3 (Multi-Client Schema Compliance):** Switching between the 6 client tabs instantaneously re-renders valid JSON/YAML matching the official format for each AI client.
- [ ] **INVARIANT_101_4 (Clipboard & Download Execution):** Clicking "Copy Combined Config" copies the exact text to system clipboard and displays "Copied!"; clicking "Download" triggers a browser download with appropriate filename (`claude_desktop_config.json`, `mcp.json`, etc.).
- [ ] **INVARIANT_101_5 (Portal Parity):** Configuration basket functions identically on `docs/index.html` and `docs/updates.html`.
- [ ] **INVARIANT_101_6 (Syntax Cleanliness):** `node -c docs/app.js && node -c docs/updates.js` passes with zero errors.

---

## 4. Deliverables

1. `docs/index.html` & `docs/updates.html`: Added `#bottomDrawer` and `#configModal` dialog markup.
2. `docs/app.js` & `docs/updates.js`: Basket state management, checkbox injection, multi-client config generation logic, clipboard copy and file download handlers.
3. `docs/style.css`: Floating bottom drawer, selected card states, and modal tab styles.

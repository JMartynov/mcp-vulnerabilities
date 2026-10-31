# Task 106: Card Footer 1-Click Client Copy & In-Modal Toolset Search (P1)

**Subsystem:** Card & Modal UX (`docs/app.js`, `docs/style.css`, `docs/index.html`)  
**Priority:** `P1`  
**Parent Plan:** [master_plan_wave20_mcp_fingerprints_capability_adoption.md](master_plan_wave20_mcp_fingerprints_capability_adoption.md)

---

## 1. Objective & Problem Statement

Developers frequently browse the MCP Directory with an immediate goal: copy the snippet for a single trusted server (e.g. Claude Desktop or Cursor configuration) into their local editor. Currently, this requires clicking "Inspect Server & Versions", waiting for the shard to load, finding the config export section, selecting the client, and copying. This multi-step flow adds unnecessary friction.

Furthermore, once inside `#server-modal` for enterprise servers (such as GitHub, AWS, Kubernetes, or Slack connectors exporting 40–100+ tools), scrolling through un-filterable tool cards to inspect parameter schemas or risk assessments is cumbersome.

This task delivers two high-impact workflow optimizations:
1. Direct **1-Click Copy Buttons (`[ 📋 Claude ]` and `[ 📋 Cursor ]`)** located in directory card footers for instant single-server config generation pinned to the recommended safe version.
2. A high-speed **`#modalToolSearch` input** inside `#server-modal` providing real-time text filtering across tool names, descriptions, and parameter names.

---

## 2. Detailed Technical Requirements

### 2.1 Card Footer 1-Click Copy Buttons (`docs/app.js` & `docs/style.css`)
1. In `renderDirectoryCards()`, expand `.server-card-footer`:
   ```html
   <div class="server-card-footer">
     <div class="card-links">
       ${s.repository_url ? `<a href="${escapeHtml(s.repository_url)}" target="_blank" rel="noopener" class="card-link">📁 Repo</a>` : ""}
       ${s.homepage_url ? `<a href="${escapeHtml(s.homepage_url)}" target="_blank" rel="noopener" class="card-link">🌐 Home</a>` : ""}
     </div>
     <div class="card-footer-actions">
       <button type="button" class="btn btn-quick-copy" data-pkg="${escapeHtml(s.package_name)}" data-client="claude" title="Copy Claude Desktop config for ${escapeHtml(title)}">
         📋 Claude
       </button>
       <button type="button" class="btn btn-quick-copy" data-pkg="${escapeHtml(s.package_name)}" data-client="cursor" title="Copy Cursor mcp.json config for ${escapeHtml(title)}">
         📋 Cursor
       </button>
       <button type="button" class="btn btn-inspect" data-pkg="${escapeHtml(s.package_name)}" data-shard="${escapeHtml(s.shard_file || "")}">
         🔍 Inspect
       </button>
     </div>
   </div>
   ```
2. Delegated Click Handler on `#servers-container`:
   - Intercept clicks on `.btn-quick-copy`.
   - Extract `pkgName` and `client` (`claude` or `cursor`).
   - Find server record from `catalogIndex`.
   - Build single-server configuration object:
     * Pin to `s.recommended_safe_version` (or safe release).
     * Format as standard Claude `mcpServers` snippet or Cursor format.
   - Write formatted JSON string to `navigator.clipboard.writeText()`.
   - Provide visual feedback: temporarily change button text to `✅ Copied!` for 1.8 seconds, then revert to original label.

### 2.2 In-Modal Toolset Search (`docs/index.html` & `docs/app.js`)
1. In `docs/index.html`, inside `#server-modal-body` above `#modal-tools-list`:
   ```html
   <div class="modal-tools-header">
     <h3 class="modal-section-title">Declared Tools & Capability Signatures</h3>
     <div class="modal-tool-search-wrap">
       <span class="search-icon">🔍</span>
       <input type="search" id="modalToolSearch" placeholder="Filter tools, parameters, descriptions..." aria-label="Search tools in modal">
       <span id="modalToolSearchCount" class="modal-search-count"></span>
     </div>
   </div>
   <div class="modal-tools-container" id="modal-tools-list"></div>
   ```
2. Real-Time Filtering in `docs/app.js`:
   - Wire `input` event listener on `#modalToolSearch`.
   - On input:
     * Retrieve search string `q = event.target.value.toLowerCase().trim()`.
     * Query all rendered tool cards inside `#modal-tools-list` (`.tool-detail-card`).
     * Check if `tool_name.includes(q)`, `description.includes(q)`, or any parameter name includes `q`.
     * Toggle element visibility: `card.style.display = match ? "block" : "none"`.
     * Update `#modalToolSearchCount` with `Showing X of Y tools` (or clear if query is empty).
     * If zero matches: show `<div class="no-tools-found">No tools match "${escapeHtml(q)}"</div>`.
   - Reset: When opening modal or switching version dropdown, reset `#modalToolSearch.value = ""` and show all tool cards.

### 2.3 Visual Styling (`docs/style.css`)
1. Style `.btn-quick-copy`:
   - Compact button (`font-size: 0.75rem`, `padding: 0.3rem 0.55rem`), subtle border, translucent dark background.
   - Hover effect: border-color `var(--primary)`, color `var(--primary)`.
2. Style `.modal-tool-search-wrap`:
   - Flex layout with relative input container, width `280px` on desktop, full-width on mobile.
   - Monospace count pill `#modalToolSearchCount` with subtle text muted styling.

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_106_1 (Card Footer 1-Click Copy Execution):** Clicking `[ 📋 Claude ]` on any directory card writes a valid, parseable JSON object (`{"mcpServers": { ... } }`) to clipboard with the server pinned to its `recommended_safe_version`.
- [ ] **INVARIANT_106_2 (Button Feedback Transition):** Button updates text to `✅ Copied!` immediately on click, and reverts to `📋 Claude` after ~1.8 seconds.
- [ ] **INVARIANT_106_3 (In-Modal Tool Search Precision):** For a server with 50 tools, typing a parameter name (e.g. `filepath`) filters the list to only tool cards declaring that parameter.
- [ ] **INVARIANT_106_4 (Version Switch Reset):** Switching the version selector dropdown in `#server-modal` clears `#modalToolSearch` and renders all tools for the selected version.
- [ ] **INVARIANT_106_5 (Syntax Cleanliness):** `node -c docs/app.js` passes with zero errors.

---

## 4. Deliverables

1. `docs/app.js`: Card footer quick-copy generator and delegated handlers, in-modal tool search filter engine and reset hooks.
2. `docs/index.html`: Added `#modalToolSearch` input and count wrapper to `#server-modal`.
3. `docs/style.css`: Quick-copy button styles and modal tool search layout.

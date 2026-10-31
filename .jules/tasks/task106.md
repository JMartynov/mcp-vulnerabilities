# Task Contract: Task 106 — Card Footer 1-Click Client Copy & In-Modal Toolset Search (P1)

### 1. Context & Objective:
Deliver two workflow enhancements for the MCP directory and server modal:
1. Direct 1-Click Copy Buttons (`[ 📋 Claude ]` and `[ 📋 Cursor ]`) located in directory card footers (`.server-card-footer`):
   - In `renderDirectoryCards()` in `docs/app.js`:
     Add `.btn-quick-copy` buttons for `claude` and `cursor`.
   - Delegated click handler on `#servers-container`:
     * Generate single-server config snippet pinned to `s.recommended_safe_version` (or safe release).
     * For Claude: `{"mcpServers": { "<name>": { ... } } }`.
     * For Cursor: standard Cursor MCP format.
     * Copy JSON to clipboard using `navigator.clipboard.writeText()`.
     * Temporary visual feedback on button: change text to `✅ Copied!` for 1.8 seconds, then revert to original text.
2. In-Modal Toolset Search (`#modalToolSearch`) in `#server-modal`:
   - In `docs/index.html`: Inside `#server-modal-body` above `#modal-tools-list`, add a search bar:
     ```html
     <div class="modal-tools-header">
       <h3 class="modal-section-title">Declared Tools & Capability Signatures</h3>
       <div class="modal-tool-search-wrap">
         <span class="search-icon">🔍</span>
         <input type="search" id="modalToolSearch" placeholder="Filter tools, parameters, descriptions..." aria-label="Search tools in modal">
         <span id="modalToolSearchCount" class="modal-search-count"></span>
       </div>
     </div>
     ```
   - In `docs/app.js`:
     * Live search handler filtering rendered tool cards by matching tool name, description, or parameter name.
     * Update `#modalToolSearchCount` with `Showing X of Y tools`.
     * Show empty state notice if no tools match.
     * Reset `#modalToolSearch.value = ""` and show all cards when opening the modal or changing the version dropdown.
3. In `docs/style.css`:
   - Style `.btn-quick-copy`, `.modal-tools-header`, `.modal-tool-search-wrap`, `.modal-search-count`.

### 2. Files to Modify:
- `docs/app.js`
- `docs/index.html`
- `docs/style.css`

### 3. Strict Guardrails:
- Pure client-side JavaScript, HTML, and CSS.
- Verify syntax with `node -c docs/app.js`.

### 4. Defaults when blocked:
- If a rule above cannot be met, leave that part as it was, list it in the summary with the reason, and continue. Do not ask questions.

### 5. Completion Directive:
- Implement all requested changes, verify JavaScript syntax, and finalize your response directly with a concise summary. Do not ask conversational follow-up questions, so the task cleanly transitions to Completed.

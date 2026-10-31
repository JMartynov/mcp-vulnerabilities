# Task 104: In-Card Tool Drawer with Real-Time Microsearch (P1)

**Subsystem:** Directory Card Explorer (`docs/app.js`, `docs/style.css`, `docs/index.html`)  
**Priority:** `P1`  
**Parent Plan:** [master_plan_wave20_mcp_fingerprints_capability_adoption.md](master_plan_wave20_mcp_fingerprints_capability_adoption.md)

---

## 1. Objective & Problem Statement

Currently, directory cards display up to 5 tool badges and a simple "+N more" pill that merely toggles the remaining static tool pills into an unformatted block. In servers with 20 to 100+ tools (e.g. cloud platform connectors, database servers, or GitHub toolsets), expanding this list creates massive visual clutter. Users have no way to quickly locate a specific tool (such as `create_pull_request` or `query_database`) without either opening the full modal or visually scanning dozens of pills.

This task equips directory cards with an **Interactive In-Card Tool Drawer with Real-Time Microsearch**:
1. An "Explore Tools ▾ (N)" / "Hide Tools ▴" toggle button expanding an integrated card sub-panel (`.inline-tool-drawer`).
2. A fast, in-card real-time microsearch `<input>` that filters tool pills on keystroke with zero latency.
3. A dynamic match counter badge `[ X / Y ]` (e.g. `[ 3 / 42 ]`) giving immediate visual feedback on tool discoverability.

---

## 2. Detailed Technical Requirements

### 2.1 In-Card Drawer DOM & Template (`docs/app.js`)
1. In `renderDirectoryCards()`, enhance the `.server-tools-row` rendering:
   - If `s.tools_count === 0`: Keep the "No static tools declared (Remote Endpoint / Gateway)" badge.
   - If `s.tools_count > 0`:
     * Render the initial 4 preview pills.
     * Render the drawer toggle button:
       ```html
       <button type="button" class="btn-tool-drawer-toggle" data-pkg="${escapeHtml(s.package_name)}" aria-expanded="${isExpanded ? "true" : "false"}">
         ${isExpanded ? "Hide Tools ▴" : `Explore Tools ▾ (${s.tools_count})`}
       </button>
       ```
     * Render the drawer container `.inline-tool-drawer` (rendered with `style="display: ${isExpanded ? 'block' : 'none'};"`):
       ```html
       <div class="inline-tool-drawer" id="toolDrawer_${escapeHtml(s.package_name)}">
         <div class="tool-drawer-header">
           <div class="microsearch-wrap">
             <span class="microsearch-icon">🔍</span>
             <input type="search" class="tool-microsearch-input" data-pkg="${escapeHtml(s.package_name)}" placeholder="Filter tools in ${escapeHtml(title)}..." aria-label="Filter tools for ${escapeHtml(s.package_name)}">
           </div>
           <span class="tool-match-badge" id="matchBadge_${escapeHtml(s.package_name)}">[ ${s.tools_sample ? s.tools_sample.length : 0} / ${s.tools_count} ]</span>
         </div>
         <div class="tool-drawer-pills" id="toolPills_${escapeHtml(s.package_name)}">
           ${allToolsPillsHtml}
         </div>
       </div>
       ```

### 2.2 Live Microsearch Filtering Engine (`docs/app.js`)
1. Implement delegated event handling on `#servers-container` for `input` events on `.tool-microsearch-input`:
   - Retrieve `pkgName` from `dataset.pkg`.
   - Get query: `const q = event.target.value.toLowerCase().trim();`.
   - Query all tool pills within `#toolPills_${pkgName}` (`.tool-pill`).
   - Iterate over pills:
     * Check if `toolName.toLowerCase().includes(q)`.
     * Toggle visibility: `pill.style.display = match ? "inline-flex" : "none"`.
     * Track count of matching tools: `matchCount`.
   - Update match badge `#matchBadge_${pkgName}` text content:
     `[ ${matchCount} / ${totalTools} ]`.
   - If `matchCount === 0`: render `<div class="no-tool-matches">No tools match "${escapeHtml(q)}"</div>`; remove when matches exist.
2. Toggle behavior:
   - Clicking `.btn-tool-drawer-toggle` toggles package presence in `expandedToolServers` set.
   - Sets `aria-expanded` and toggles `.inline-tool-drawer` display between `none` and `block`.
   - Focuses the `.tool-microsearch-input` upon expansion for instant keyboard typing.

### 2.3 Visual Styling & Animation (`docs/style.css`)
1. Style `.inline-tool-drawer`:
   - Background: `rgba(15, 23, 42, 0.75)`, border: `1px solid var(--border-color)`, border-radius: `6px`, padding: `0.75rem`, margin-top: `0.5rem`.
2. Style `.microsearch-wrap`:
   - Relative wrapper with positioned search magnifying glass icon and dark styled input.
   - Input: background `var(--bg-card)`, border `1px solid var(--border-color)`, font-size `0.8rem`, padding `0.25rem 0.5rem 0.25rem 1.75rem`, border-radius `4px`, color `var(--text-main)`.
3. Style `.tool-match-badge`:
   - Monospace font (`font-family: monospace`), font-size `0.75rem`, color `var(--primary)`, background `rgba(56, 189, 248, 0.1)`, padding `0.2rem 0.4rem`, border-radius `4px`.

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_104_1 (Drawer Toggle & State Retention):** Clicking "Explore Tools ▾" opens the drawer and focuses the microsearch input; clicking "Hide Tools ▴" collapses it. State persists across infinite scroll batches.
- [ ] **INVARIANT_104_2 (Instant Substring Filtering):** Typing "get" in a server with 25 tools instantaneously hides all tools without "get" in their names.
- [ ] **INVARIANT_104_3 (Dynamic Match Counter Accuracy):** The counter badge displays exact counts: e.g. `[ 4 / 25 ]` when 4 tools match, and `[ 0 / 25 ]` when no tools match.
- [ ] **INVARIANT_104_4 (Inspector Deep-Link from Drawer):** Clicking any tool pill inside `.inline-tool-drawer` triggers `openInspectorModal(pkgName, toolName)` identically to main card pills.
- [ ] **INVARIANT_104_5 (Syntax Cleanliness):** `node -c docs/app.js` passes with zero errors.

---

## 4. Deliverables

1. `docs/app.js`: In-card drawer generation, delegated microsearch filter handlers, dynamic badge updater, and state retention.
2. `docs/style.css`: Microsearch input, drawer header, match counter badge, and responsive tool grid styles.

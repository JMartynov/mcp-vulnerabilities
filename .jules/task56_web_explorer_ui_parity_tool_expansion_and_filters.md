# Task 56: Web Security Explorer UI Parity (Interactive Tool Expansion, Zero-Tool States & Multi-Facet Filters) (P1)

## 1. Architectural Context & Technical Objective

In `mcp-fingerprints` (Task 60), the public web catalog and updates feed underwent an interactive UI overhaul to eliminate static, dead-end elements and visual voids. 

However, in `mcp-vulnerabilities`, the web portal (`docs/index.html`, `docs/app.js`, `docs/updates.html`, `docs/updates.js`, `docs/style.css`) still exhibits legacy limitations:
1. **Unclickable `+N more` Badges**: Server cards displaying more than 5 tools render an unclickable `<span>` (e.g., `+ 8 more`) without any expand/collapse behavior.
2. **Visual Voids on Zero-Tool Servers**: Servers with 0 tools (such as remote gateways, client SDKs, or resource-only servers) render with an awkward empty gap in the card body where tools normally appear.
3. **Missing Tool Filter**: Users cannot filter the catalog or updates feed by "Has Callable Tools Only" to filter out pure gateways when searching for actionable MCP tools.
4. **Tool Tag Click Handlers**: Tool chips do not open or highlight the tool parameter schema in the inspector modal.

### Core Objectives:
1. **Interactive Tool Tag Expansion (`+N more` / `Show less ▴`)**:
   - Track expanded tool state per server card (`expandedToolServers` Set).
   - Render `+N more` with `role="button"`, `tabindex="0"`, and click/keyboard event handler `toggleToolsExpand('${serverName}')`.
   - Clicking expands all tools inline, followed by a `Show less ▴` chip that collapses back to 5 tools.
2. **Informative Zero-Tool State**:
   - When a server has 0 static tools (`tool_count === 0` or missing):
     Render an explicit, styled badge:
     ```html
     <div class="tools-section">
       <div class="tools-label">Tools (0)</div>
       <div class="no-tools-badge">No static tools declared (Remote Endpoint / Gateway)</div>
     </div>
     ```
3. **"Has Tools Only" Filter Checkbox**:
   - Add `<label class="filter-checkbox"><input type="checkbox" id="filterToolsOnly"> Has Tools Only</label>` to both `docs/index.html` and `docs/updates.html`.
   - Update filtering logic in `docs/app.js` and `docs/updates.js` to instantly hide servers with `tool_count === 0` when checked.
4. **Inspector Modal Linkage**:
   - Clicking any tool tag (`.tool-tag`) invokes `openInspectorModal('${serverName}', '${toolName}')` to inspect parameters and input schemas.
5. **Accessibility & Responsive Styling**:
   - Add hover states, focus rings, keyboard accessibility (`Enter` and `Space`), and responsive wrapping in `docs/style.css`.

---

## 2. Target Files & Documentation
- `docs/index.html`
- `docs/app.js`
- `docs/updates.html`
- `docs/updates.js`
- `docs/style.css`
- `tests/test_web_catalog_ui_parity.py`
- `docs/tasks/README.md`

---

## 3. Super Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Tool Expansion & Collapse Invariant
- **Preconditions**: A server card with 12 tools (e.g. `@modelcontextprotocol/server-filesystem`).
- **Test Steps**:
  1. Inspect initial render: exactly 5 tool tags and one `+ 7 more` chip must be rendered.
  2. Simulate click on `+ 7 more`.
  3. Verify all 12 tool tags are visible and the trailing chip changes to `Show less ▴`.
  4. Simulate click on `Show less ▴`.
  5. Verify display returns to 5 tool tags and `+ 7 more`.
- **Invariants**:
  - [x] **INVARIANT_1A (Initial Count)**: Initial tool chip count MUST NOT exceed 5 plus the expansion chip.
  - [x] **INVARIANT_1B (Full Expansion)**: Expanding MUST display all $N$ tools without DOM re-creation artifacts.
  - [x] **INVARIANT_1C (Keyboard Accessibility)**: Pressing `Enter` or `Space` on `.tool-tag-more` MUST toggle the expansion state.

### Scenario 2: Informative Zero-Tool State Invariant
- **Preconditions**: A server card with `tool_count: 0` (e.g. `@juspay/neurolink`).
- **Test Steps**:
  1. Render server card.
- **Invariants**:
  - [x] **INVARIANT_2A (No Blank Gap)**: Card body MUST render `.no-tools-badge` containing `"No static tools declared"`.
  - [x] **INVARIANT_2B (No Expansion Chip)**: `+N more` MUST NOT be rendered.

### Scenario 3: "Has Tools Only" Filter Invariant
- **Preconditions**: Catalog dataset containing 70 servers with tools and 30 zero-tool gateways.
- **Test Steps**:
  1. Check `#filterToolsOnly`.
  2. Verify visible server count.
  3. Combine with an ecosystem filter (e.g. `npm`) and search query.
- **Invariants**:
  - [x] **INVARIANT_3A (Strict Exclusion)**: Zero servers with `tool_count === 0` may be visible when `#filterToolsOnly` is checked.
  - [x] **INVARIANT_3B (Filter Conjunction)**: Operates conjunctively (`AND`) with ecosystem, vulnerability status, and search filters.
  - [x] **INVARIANT_3C (Uncheck Restoration)**: Unchecking `#filterToolsOnly` immediately restores the zero-tool servers to the view.

### Scenario 4: Tool Tag Inspector Modal Linkage Invariant
- **Preconditions**: Click on tool tag `read_file`.
- **Test Steps**:
  1. Click `.tool-tag[data-tool="read_file"]`.
- **Invariants**:
  - [x] **INVARIANT_4A**: Opens inspector modal with `read_file` highlighted and its JSON schema rendered.

---

## 4. Implementation Steps

1. Update `docs/style.css`:
   - Add styles for `.tool-tag-more`, `.tool-tag-more:hover`, `.no-tools-badge`, `.filter-checkbox`.
2. Update `docs/index.html` & `docs/updates.html`:
   - Add `#filterToolsOnly` checkbox control to the filter bars.
3. Update `docs/app.js`:
   - Define `let expandedToolServers = new Set();` inside the top of the IIFE.
   - Implement `window.toggleToolsExpand = function(serverName) { ... }`.
   - Render `.no-tools-badge` when `tool_count === 0` (or `s.tools.length === 0`).
   - Update `applyDirectoryFilters()` to evaluate `filterToolsOnly`.
   - Implement `window.openInspectorModal = function(serverName, toolName) { ... }` and bind `.tool-tag` clicks.
4. Update `docs/updates.js`:
   - Mirror tool tag expansion, zero-tool badge, and filter toggle in the updates feed.
5. Author comprehensive verification tests in `tests/test_web_catalog_ui_parity.py`:
   - Follow the same pattern as `tests/test_web_portal_ui.py` and `tests/test_web_ui.py` using Python file inspection, AST/regex parsing, and structural assertions.
   - STRICT MANDATE: DO NOT use Playwright, Selenium, or headless browser binaries (no browser executable is installed).
   - STRICT MANDATE: DO NOT modify, truncate, or delete any files under `docs/data/` (such as `docs/data/mcp_catalog_index.json`).
   - STRICT MANDATE: Clean up any temporary scratch files (`patch_*.py`) before finalizing.
6. Verify `pytest -q tests/test_web_catalog_ui_parity.py` passes 100% and `pytest -q` passes 100%.

## Non-Interactive Completion Directive
Execute this task end-to-end without asking interactive questions. Implement all UI and styling changes cleanly across `docs/index.html`, `docs/app.js`, `docs/updates.html`, `docs/updates.js`, and `docs/style.css`. Add the comprehensive test suite in `tests/test_web_catalog_ui_parity.py`, verify that all tests pass (`pytest -q`), clean up scratch files, and conclude directly with a complete patch so the remote environment cleanly transitions to `Completed`.

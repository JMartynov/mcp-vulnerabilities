# Task Contract: Task 104 — In-Card Tool Drawer with Real-Time Microsearch (P1)

### 1. Context & Objective:
Equip directory cards on `docs/index.html` with an Interactive In-Card Tool Drawer with Real-Time Microsearch:
- In `renderDirectoryCards()` in `docs/app.js`:
  * If server has tools (`tools_count > 0`), render the initial preview pills plus an "Explore Tools ▾ (N)" / "Hide Tools ▴" toggle button (`.btn-tool-drawer-toggle`, `data-pkg="${escapeHtml(s.package_name)}"`).
  * Render `.inline-tool-drawer` sub-panel containing:
    - Microsearch input (`.tool-microsearch-input`, `data-pkg="..."`, placeholder `Filter tools in <title>...`).
    - Dynamic match counter badge `[ X / Y ]` (`#matchBadge_<pkg>`).
    - Tool pills container (`#toolPills_<pkg>`).
- Delegated event handling in `docs/app.js`:
  * On input in `.tool-microsearch-input`: Filter tool pills within the drawer in real time by substring match on tool name.
  * Update match badge count `[ matchCount / totalCount ]`.
  * If zero matches, render inline notice `<div class="no-tool-matches">No tools match "..."</div>`.
  * On drawer toggle button click: Toggle expanded state (persist in a set so state is retained across re-renders/scrolling), toggle display between `none` and `block`, and auto-focus the search input when expanding.
  * Clicking any tool pill inside `.inline-tool-drawer` triggers `openInspectorModal(pkgName, toolName)` identically to main card pills.
- Styling in `docs/style.css`:
  * Style `.inline-tool-drawer`, `.microsearch-wrap`, `.tool-microsearch-input`, `.tool-match-badge`, `.btn-tool-drawer-toggle`.

### 2. Files to Modify:
- `docs/app.js`
- `docs/style.css`

### 3. Strict Guardrails:
- Pure vanilla JavaScript and CSS; zero external libraries.
- Maintain existing card rendering performance; use event delegation on `#servers-container`.
- Verify JavaScript syntax with `node -c docs/app.js`.

### 4. Defaults when blocked:
- If a rule above cannot be met, leave that part as it was, list it in the summary with the reason, and continue. Do not ask questions.

### 5. Completion Directive:
- Implement all requested changes, verify JavaScript syntax, and finalize your response directly with a concise summary. Do not ask conversational follow-up questions, so the task cleanly transitions to Completed.

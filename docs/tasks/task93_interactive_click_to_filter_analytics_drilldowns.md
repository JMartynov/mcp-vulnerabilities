# Task 93: Interactive Click-to-Filter Drilldowns on Analytics Portal (P1)

**Subsystem:** Analytics Web Portal (`docs/analytics.html`, `docs/app.js`)  
**Priority:** `P1`  
**Parent Plan:** [IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md](IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md)

---

## 1. Objective & Problem Statement
Currently, `docs/analytics.html` provides statistical charts (*Top 10 Vulnerable Tools*, *OWASP MCP Category Breakdown*, *Tool Shadowing Risk*, *Ecosystem Distribution*, *Secrets Perimeter*), but all elements are static readouts. When a security architect identifies a critical category (e.g. "MCP05 — Command Injection" or a shadowed tool name like "search"), they cannot click to see which servers are affected. Adding interactive click-through links to `index.html` with pre-filled filter parameters bridges the gap between macro threat intelligence and concrete server inspection.

---

## 2. Detailed Technical Requirements

### 2.1 Click-to-Filter Anchors & Event Handling (`docs/analytics.html`)
1. In `docs/analytics.html`, update the JavaScript render logic to wrap chart items in clickable filter links directed to `index.html`:
   - **Top 10 Vulnerable Tools**: Each tool bar links to `index.html?q=<tool_name>&status=vulnerable` (e.g. `index.html?q=connect&status=vulnerable`).
   - **OWASP MCP Category Breakdown**: Each category row links to `index.html?q=<category_name>&status=vulnerable` (e.g. `index.html?q=Command+Injection&status=vulnerable`).
   - **Tool Shadowing Risk**: Each high-entropy tool pill links to `index.html?q=<tool_name>&sort=tools_desc` (e.g. `index.html?q=search`).
   - **Ecosystem Distribution**: Each ecosystem count bar links to `index.html?eco=<ecosystem_name>` (e.g. `index.html?eco=pypi`).
   - **Zero-Day Gap Section**:
     * "Available Safe Patch" card links to `index.html?status=vulnerable&patch=available`.
     * "NO KNOWN FIX (Zero-Day)" card links to `index.html?status=vulnerable&patch=unpatched`.
2. Style hover effects:
   - Add `.chart-clickable-row` styles with subtle hover highlights (`background: rgba(59, 130, 246, 0.1)`, pointer cursor, and external drill-down arrow icon `↗`).

### 2.2 Deep-Link Query Consumer in Directory (`docs/app.js`)
1. In `docs/app.js`, ensure `init()` parses `patch` query parameter (`available` vs `unpatched`):
   - When `patch=available`: filter to `server.is_vulnerable && server.recommended_safe_version`.
   - When `patch=unpatched`: filter to `server.is_vulnerable && !server.recommended_safe_version`.
2. When query string matches a tool or OWASP keyword, filter directory cards matching either tool names in `tools_sample` or advisory descriptions.

---

## 3. Acceptance Criteria
- [ ] Hovering over analytics chart rows displays a pointer cursor and drill-down indicator (`↗`).
- [ ] Clicking a vulnerable tool (e.g. `connect`) navigates to `index.html?q=connect&status=vulnerable` with filtered results.
- [ ] Clicking an OWASP category navigates to `index.html` filtered by that category.
- [ ] Clicking Zero-Day gap cards filters specifically between patched and zero-day unpatched servers.
- [ ] Browser history navigation works smoothly without broken states.

---

## 4. Operational Directives
- **Non-Interactive Completion Directive:** Implement and verify autonomously.
- **Accessibility:** Add `title="Drill down to affected servers in Directory"` to all generated drill-down links.

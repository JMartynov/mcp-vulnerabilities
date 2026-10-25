# Task 90: Directory Multi-Criteria Sorting & URL Deep-Linking (P0)

**Subsystem:** Front-End Explorer (`docs/index.html`, `docs/app.js`, `docs/style.css`)  
**Priority:** `P0`  
**Parent Plan:** [IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md](IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md)

---

## 1. Objective & Problem Statement
With 6,289 indexed servers in the directory, users have no way to sort cards by severity or surface complexity. Furthermore, refreshing the browser or sharing a URL resets search queries, active tab selection, and open server modals, making it impossible to share direct links to specific vulnerability assessments.

---

## 2. Detailed Technical Requirements

### 2.1 Multi-Criteria Sorting Control (`docs/index.html` & `docs/app.js`)
1. In `docs/index.html` inside `.search-filter-section` (near `.search-wrapper`), add a styled sort dropdown:
   - `<select id="sort-select" aria-label="Sort MCP Servers">`
   - Options:
     * `risk_desc`: "Highest Risk First (CRITICAL ➔ LOW)" (Default when viewing Vulnerable servers)
     * `advisories_desc`: "Most Advisories / CVEs First"
     * `tools_desc`: "Largest Tool Surface (Most Tools First)"
     * `name_asc`: "Package Name (A ➔ Z)"
     * `name_desc`: "Package Name (Z ➔ A)"
2. In `docs/app.js`, add `applySorting(servers, criteria)`:
   - `risk_desc`: Sort by `composite_risk_tier` severity weight (`CRITICAL: 4, HIGH: 3, MEDIUM/MODERATE: 2, LOW: 1`).
   - `advisories_desc`: Sort by `vulnerable_versions_count` or total advisory count descending.
   - `tools_desc`: Sort by `tools_count` descending.
   - `name_asc` / `name_desc`: Locale-aware case-insensitive package name sorting.
3. Wire the sort selector to re-render the filtered directory cards immediately.

### 2.2 Bidirectional URL Deep-Linking & History State Synchronization (`docs/app.js`)
1. Synchronize the UI state with browser `window.location.search`:
   - `q`: Search query string
   - `tab`: Active tab (`directory`, `advisories`, `audit`)
   - `status`: Security status filter (`all`, `vulnerable`, `clean`)
   - `risk`: Capability risk tier filter (`all`, `critical`, `high`, `medium`, `low`)
   - `eco`: Ecosystem filter (`all`, `npm`, `pypi`, `github`, `generic`)
   - `tools_only`: Boolean (`1` or `0`)
   - `sort`: Selected sort option
   - `server`: Pinned package name to automatically open in `#server-modal` on load
   - `version`: Target version to select within `#server-modal`
2. On page load (`init()`): Parse `URLSearchParams` and restore all search inputs, active filter buttons, sort selection, active tab, and open the requested `#server-modal` if `server` parameter is present.
3. Update URL with `history.replaceState` on search/filter changes, and `history.pushState` when opening/closing `#server-modal` so browser Back/Forward navigation works naturally.

---

## 3. Acceptance Criteria
- [ ] Sort dropdown renders seamlessly across desktop and mobile.
- [ ] Sorting by "Highest Risk First" puts CRITICAL composite risk servers at the top.
- [ ] Navigating to `index.html?server=5ire` opens the `#server-modal` for `5ire` automatically.
- [ ] Navigating to `index.html?tab=audit` activates Tab 3 directly.
- [ ] Changing search filters updates URL query params without reloading the page.
- [ ] `node -c docs/app.js` passes with zero errors.

---

## 4. Operational Directives
- **Non-Interactive Completion Directive:** Complete implementation autonomously without awaiting input.
- **Accessibility Invariant:** Ensure the `<select>` has an accessible label (`aria-label="Sort MCP servers"`).

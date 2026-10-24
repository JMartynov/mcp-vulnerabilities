# Task 73: Web Portal Visual Styling, Card De-Duplication & Composite Risk (P0)

## 1. Architectural Context & Technical Objective

Live Chrome DevTools inspection of [index.html](https://jmartynov.github.io/mcp-vulnerabilities/) and [updates.html](https://jmartynov.github.io/mcp-vulnerabilities/updates.html) revealed major visual presentation bugs and information hierarchy defects:
1. **Unstyled Badges:** `app.js` and `updates.js` render `.badge.risk-${tier}` and `.badge.risk-${sev}`, but `style.css` only defines `.badge-critical`, `.badge-high`, etc. Consequently, every risk badge and advisory severity badge renders transparent with no background color and no border.
2. **Title Duplication:** 100% of the 6,159 indexed servers have identical `display_name` and `package_name`, causing both pages to print the same string twice in every card header.
3. **Redundant Badges on Updates:** `updates.html` prints `🔴 New Security Vulnerability` in the header, and immediately underneath prints `🔴 Vulnerable`.
4. **False Risk: LOW:** Every server defaults to `Risk: LOW` even when afflicted by verified Critical Remote Code Execution CVEs.
5. **Empty Tools Row Gap:** Servers with 0 tools render an empty `<div class="server-tools-row">` with `margin-bottom: 16px`.
6. **Broken CSS Variables:** `.no-tools-badge` references undefined `--bg-alt` and `--border`.
7. **Accessibility Issues:** Form inputs (`#directory-search-input`, `#advisory-search-input`) lack labels and `aria-label` attributes.

This task resolves all card styling, hierarchy, de-duplication, accessibility, and composite risk presentation issues across both web pages.

---

## 2. Target Files & Isolation Boundaries
- Scope: `docs/style.css`, `docs/app.js`, `docs/updates.js`, `docs/index.html`, `docs/updates.html`
- Deliverable: Pixel-perfect, contrast-compliant cards with proper badge styling, zero duplicate titles, and composite risk scoring.

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: CSS Badge Reconciliation & Advisory Selector Alignment
- **Preconditions**: Render cards with risk tiers (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`).
- **Invariants**:
  - [x] **INVARIANT_1A (Badge Styling)**: All `.badge.risk-*` elements must resolve with explicit background colors, borders, and contrast ratios conforming to WCAG AA.
  - [x] **INVARIANT_1B (Advisory Card Selectors)**: Add `.advisory-card-header`, `.advisory-id` (monospace, `#60a5fa`, bold), `.advisory-summary`, and `.advisory-pkgs code` styling in `docs/style.css`.
  - [x] **INVARIANT_1C (CSS Variable Fix)**: Replace invalid `--bg-alt` and `--border` with `--surface-hover` and `--border-color`.

### Scenario 2: Server Card De-Duplication & Redundancy Suppression
- **Preconditions**: Render server cards in `index.html` and `updates.html`.
- **Invariants**:
  - [x] **INVARIANT_2A (Title De-Duplication)**: If `s.display_name === s.package_name` or `!s.display_name`, render only `<h3 class="server-title">${s.package_name}</h3>`. Only render `.server-pkg-name` when `display_name` differs.
  - [x] **INVARIANT_2B (Updates Badge Redundancy)**: In `updates.html`, suppress `🔴 Vulnerable` if the `🔴 New Security Vulnerability` badge is already rendered in the header.
  - [x] **INVARIANT_2C (Empty Tools Gap)**: Hide `.server-tools-row` when empty (`.server-tools-row:empty { display: none; margin: 0; }`).

### Scenario 3: Composite Risk Tier Calculation & Accessibility
- **Preconditions**: Render a server afflicted by a high or critical CVE (e.g. Neo4j Cypher `CVE-2025-10193`).
- **Invariants**:
  - [x] **INVARIANT_3A (Composite Risk)**: In `app.js` and `updates.js`, compute effective risk: if `s.is_vulnerable`, reflect the highest CVE severity instead of defaulting to `Risk: LOW`.
  - [x] **INVARIANT_3B (Form Accessibility)**: Add `aria-label="Search MCP servers"` and `aria-label="Search security advisories"` to search inputs on both pages.

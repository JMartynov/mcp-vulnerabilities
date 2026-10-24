# Task 82: CSS Design Tokens, Sub-Tab Reset, Sparkline `viewBox` & UI Hygiene (P1)

**Defect Reference:** `DEFECT-W14-06`, `DEFECT-W14-07`, `DEFECT-W14-08`, `DEFECT-W14-09`, `DEFECT-W14-10` ([`docs/reports/code_review_wave14_portal_and_analytics.md`](../reports/code_review_wave14_portal_and_analytics.md))  
**Target Wave:** Wave 15A (Wave 14 Code Review Remediation)  
**Priority:** `P1` (Visual Polish, Accessibility & Hygiene Fixes to reach 100/100 Scorecard)

---

## 1. Architectural Context & Technical Objective

The Wave 14 Code Review identified 5 Medium/Low UI and CSS hygiene defects across `docs/style.css`, `docs/analytics.html`, `docs/app.js`, `docs/updates.js`, and `docs/updates.html`:
1. **`DEFECT-W14-06` (Undefined CSS Variables & Missing `.badge-eco`)**:
   - `docs/style.css` (lines 1256, 1281, 1314, 1318) and `docs/analytics.html` (lines 17, 46, 54, 281) reference `--bg-tertiary`, `--primary-color`, `--bg-card`, `--bg-hover`, and `--badge-bg`, none of which are defined in `:root`. Consequently, `.badge-transport`, `.fp-badge`, `.primitive-tab-btn.active`, `#modal-env-vars-container`, and `.chart-card` render with transparent backgrounds.
   - `docs/app.js` and `docs/updates.js` render `<span class="badge badge-eco">`, which has no CSS rule in `docs/style.css`.
2. **`DEFECT-W14-07` (Modal Primitive Sub-Tab Desynchronization)**:
   - In `docs/app.js` (`selectVersion()`) and `docs/updates.js` (`selectVersion()`), switching between version pills updates the tools/prompts/resources containers in the background without resetting the active sub-tab button/pane to `"tools"`, leaving the active tab indicator desynchronized if the user previously viewed Prompts or Resources.
3. **`DEFECT-W14-08` (Missing Keyboard Accessibility on `.fp-badge`)**:
   - `.fp-badge` elements use inline `onclick` without `role="button"`, `tabindex="0"`, or `Enter`/`Space` keyboard activation.
4. **`DEFECT-W14-09` (Missing `rel="noopener"` on External Links)**:
   - Syndication feed links (`data/feed.atom`, `data/feed.json`) in `docs/updates.html` use `target="_blank"` without `rel="noopener"`.
5. **`DEFECT-W14-10` (Responsive Sparkline `viewBox`)**:
   - `<svg id="historical-sparkline">` in `docs/updates.html` and `renderSparkline()` in `docs/updates.js` lack a `viewBox="0 0 1000 80"` and `preserveAspectRatio="none"`, preventing responsive scaling on window resize or mobile orientation changes.

This task resolves all five defects to bring the Wave 14/15 frontend quality scorecard to **100 / 100**.

---

## 2. Target Files & Isolation Boundaries

- **Primary Files:**
  - `docs/style.css`
  - `docs/analytics.html`
  - `docs/updates.html`
  - `docs/updates.js`
  - `docs/app.js`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: CSS Design Tokens & `.badge-eco` Definition (`INVARIANT_82_1A`)
- **Invariants**:
  - [ ] **INVARIANT_82_1A (`:root` Token Completeness)**: `:root` in `docs/style.css` defines:
    - `--bg-tertiary: #1e293b;`
    - `--primary-color: #3b82f6;`
    - `--bg-card: #121826;`
    - `--bg-hover: #1a2235;`
    - `--badge-bg: rgba(148, 163, 184, 0.15);`
  - [ ] **INVARIANT_82_1B (`.badge-eco` Rule)**: `docs/style.css` defines `.badge-eco` with high-contrast background, text color, and border (`background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3);`).

### Scenario 2: Modal Primitive Sub-Tab Reset & Keyboard Accessibility (`INVARIANT_82_2A`)
- **Invariants**:
  - [ ] **INVARIANT_82_2A (Sub-Tab Reset on Version Switch)**: Calling `selectVersion()` in both `docs/app.js` and `docs/updates.js` resets `.primitive-tab-btn` active state to `[data-primitive-tab="tools"]` and activates `#modal-tools-tab` (hiding `#modal-prompts-tab` and `#modal-resources-tab`).
  - [ ] **INVARIANT_82_2B (`.fp-badge` Keyboard Accessibility)**: All `.fp-badge` elements rendered in `docs/app.js` and `docs/updates.js` include `role="button" tabindex="0"` and a `keydown` handler supporting `Enter` and `Space`.

### Scenario 3: Link Security & Responsive Sparkline SVG (`INVARIANT_82_3A`)
- **Invariants**:
  - [ ] **INVARIANT_82_3A (`rel="noopener"`)**: Every `<a ... target="_blank">` in `docs/updates.html` includes `rel="noopener"`.
  - [ ] **INVARIANT_82_3B (Sparkline `viewBox`)**: `<svg id="historical-sparkline">` in `docs/updates.html` and `renderSparkline()` in `docs/updates.js` set `viewBox="0 0 1000 80"` and `preserveAspectRatio="none"`, rendering coordinates against a fixed `width = 1000`, `height = 80` coordinate space.

---

## 4. Concrete Implementation Instructions

1. In `docs/style.css`, add `--bg-tertiary`, `--primary-color`, `--bg-card`, `--bg-hover`, and `--badge-bg` to `:root`, and add the `.badge-eco` class rule alongside `.badge`.
2. In `docs/app.js` and `docs/updates.js`:
   - Add `role="button" tabindex="0"` and keyboard activation (`onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();this.click();}"`) to `.fp-badge` markup.
   - Inside `selectVersion(v)`, reset the primitive sub-tab buttons and panes so `"tools"` / `#modal-tools-tab` is active.
3. In `docs/updates.html`:
   - Add `rel="noopener"` to all four `target="_blank"` feed anchor links (`data/feed.atom` and `data/feed.json` in header and footer).
   - Add `viewBox="0 0 1000 80" preserveAspectRatio="none"` to `<svg id="historical-sparkline">`.
4. In `docs/updates.js` inside `renderSparkline(history)`:
   - Set `el.historicalSparkline.setAttribute("viewBox", "0 0 1000 80")` and `el.historicalSparkline.setAttribute("preserveAspectRatio", "none")`, and use `const width = 1000; const height = 80;`.
5. Validate syntax via `node -c docs/app.js && node -c docs/updates.js` and run `.venv/bin/pytest -q`.

---

## 5. Non-Interactive Completion Directive

Complete all implementation steps, verify all invariants locally, and commit directly without asking open-ended questions so the session cleanly transitions to `Completed`.

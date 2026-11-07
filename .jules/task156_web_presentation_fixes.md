# Task 156: Web Presentation & Visual Design Polish

## Objective
Fix visual defects and layout inconsistencies discovered during automated deep visual review of the web portal:
1. `docs/updates.js`: Fix SVG sparkline distortion. `viewBox="0 0 120 24"` with `preserveAspectRatio="none"` inside an 80px high container caused extreme non-uniform stretching (rendering circles as giant sausage blobs). Update `renderSparkline` to use `viewBox="0 0 1000 80"`, compute coordinates across 1000x80 space, and add `vector-effect="non-scaling-stroke"` so the sparkline renders smoothly.
2. `docs/analytics.html`: Fix OWASP Category truncation. `.bar-label` flex basis is currently only 200px, cutting off almost all OWASP MCP categories with ellipses (`...`). Expand `.bar-label` to `flex: 0 0 280px;` (or responsive sizing with `min-width: 260px; max-width: 320px;`).
3. `docs/style.css`: Add responsive mobile `@media (max-width: 768px)` rules:
   - Allow `.header-links` to wrap nicely on mobile without overflowing.
   - Prevent `.modal-title-wrap` from colliding with `.modal-close-btn` on mobile by setting `min-width: 0; flex: 1; margin-right: 12px;` and `word-break: break-word;`.
   - Provide balanced accent borders on `.metric-card` (e.g. `.metric-critical { border-left: 4px solid var(--critical-color); }`, first card `.metric-card:first-child { border-left: 4px solid var(--accent-color); }`).
4. `docs/app.js`:
   - Fix duplicate `sha256:sha256:` prefix in `fpBadge`: strip existing prefix `s.toolset_canonical_hash.replace(/^sha256:/, '')` before formatting.
   - Fix `none ➔ none` in `el.diffSummaryRow`: if `baseHash === 'none' && targetHash === 'none'`, do not display `.diff-hash`.
   - Remove square brackets from quick-copy buttons: replace `[ 📋 Claude ]` and `[ 📋 Cursor ]` with `📋 Claude` and `📋 Cursor`.
   - Dynamically update catalog tab title count in `docs/index.html` or update static label to match total server count.

## Acceptance Criteria
1. Sparkline on `updates.html` renders smooth, undistorted lines and circles.
2. OWASP category labels on `analytics.html` display full category names without premature truncation.
3. Mobile viewport (390px) does not overflow horizontally in header links and modal title does not overlap close button.
4. Toolset canonical hash badges display `🔑 sha256:<8-chars>...` without duplicate `sha256:sha256:` prefix.
5. Modal version diff does not display `none ➔ none`.
6. Quick copy buttons display `📋 Claude` and `📋 Cursor` without square brackets.
7. All unit tests (`pytest`) continue to pass.

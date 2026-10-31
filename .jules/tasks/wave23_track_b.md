# Task: Wave 23 Track B — Web Visual & Workflow Audit (Tasks 126, 127, 128, 129)

## Overview & Mandate
You are assigned **Wave 23 Track B: Full-Surface Web Portal & Visual Workflow Audit** for `mcp-vulnerabilities`.
Your task is to execute the frontend visual, interaction, and caching audit specified across:
- `docs/tasks/task126_web_directory_infinite_scroll_visual_audit.md` (Infinite Scroll Virtualization & Directory Explorer)
- `docs/tasks/task127_web_basket_collision_config_modal_audit.md` (Multi-Server Basket, Collision Warnings & Config Modal)
- `docs/tasks/task128_web_analytics_sparklines_updates_feed_audit.md` (Analytics Dashboard, Sparklines & Updates Feeds)
- `docs/tasks/task129_web_pwa_offline_service_worker_audit.md` (PWA Offline Service Worker & Cache Hierarchy)

## Instructions & Deliverables
1. **Frontend Code Fixes & Hardening**:
   - **Fix Critical Collision Bug in `docs/app.js`**: In `window.detectCollisions` (lines 2294-2315), resolve `ReferenceError: selectedServers is not defined` by accessing the appropriate selected servers state or basket collection (`state.selectedServers` or `getSelectedServers()`).
   - **Virtualization & Infinite Scrolling**: Enhance `docs/app.js` with an `IntersectionObserver` sentinel batching mechanism (48 items per chunk) so users can scroll smoothly through the catalog without DOM node explosion or 100-card truncation.
   - **PWA Service Worker Offline Invariants**: Update `docs/sw.js` to ensure proper caching strategies for updates feeds (`docs/data/updates/`) and vulnerability definitions (`docs/data/vulnerabilities.json`), with LRU eviction for shard cache hygiene.
   - Ensure responsive layout invariants across mobile (375px), tablet (768px), and desktop (1440px) without horizontal clipping.

2. **Automated Test Suites**:
   Author and verify headless browser / DOM invariant test suites:
   - `tests/test_web_visual_directory.py`: Tests directory card DOM structure, sentinel batching logic, microsearch filtering, and risk tier badges.
   - `tests/test_web_basket_collision.py`: Tests `detectCollisions` execution without exceptions, collision alert banner DOM updates, and 6-client config generation.
   - `tests/test_web_analytics_updates.py`: Tests SemVer numerical ordering, SVG sparkline attributes, and click-to-filter drilldown URL query encoding.
   - `tests/test_web_pwa_offline.py`: Tests `sw.js` static cache manifest integrity, fetch routing rules, and offline fallback responses.

3. **Audit Report**:
   Generate `docs/reports/wave23_audits/audit_track_b_web_portal_and_workflows.md` summarizing:
   - Visual inspection results across `index.html`, `analytics.html`, `updates.html`.
   - Before/after comparison of the `detectCollisions` bug fix and infinite scrolling sentinel implementation.
   - Lighthouse / PWA caching verification and DOM node scaling metrics.

4. **Local Verification**:
   - Run `python3 -m pytest tests/test_web_*.py -q` and verify all tests pass.

## Non-Interactive Completion Directive
Complete all frontend fixes in `docs/`, author the 4 test suites under `tests/`, write the audit report in `docs/reports/wave23_audits/audit_track_b_web_portal_and_workflows.md`, verify tests pass, and commit directly without asking open-ended questions so this session cleanly transitions to `Completed`.

# Task 95: Release History Delta Calculation & Semantic Version Ordering

## Contract & Objectives
Fix the suspicious numbering, sorting, and delta metrics in the Release Updates feed and UI (`docs/updates.html`, `docs/updates.js`, and `src/mcp_vulnerabilities/updates_builder.py`):
1. **True Delta Metrics vs Snapshot Totals**:
   - `updates_builder.py` currently writes entire catalog totals (`682` advisories, `344` servers) into `new_advisories` and `new_mcp_servers` for every release.
   - Implement authentic release-over-release delta calculation: compare current unified catalog state against previous release snapshot (`docs/data/updates/v<prev_version>.json` or previous entry in `updates_history.json`).
   - Calculate genuine `new_advisories` (advisories added since previous release), `updated_advisories` (advisories modified since previous release), `new_mcp_servers` (newly cataloged servers), and `updated_mcp_versions` (new versions/patches observed).
   - If generating the very first release (`v1.0.0`) without previous history, fall back to initial catalog snapshot counts.
2. **Robust Client-Side SemVer Ordering in `docs/updates.js`**:
   - In `loadReleaseHistory()`, do not rely solely on raw array insertion order.
   - Implement SemVer-aware sorting helper (`compareSemVer(vA, vB)`) so versions are strictly sorted in descending SemVer order (e.g. `v1.2.1` > `v1.2.0` > `v1.1.6` ... `v1.0.10` > `v1.0.9` > ... `v1.0.0`).
   - Ensure versions with multi-digit patch/minor parts like `1.0.10` vs `1.0.9` are compared numerically rather than by ASCII character code.
3. **Data Repair & Historical Rebuild**:
   - Provide clean, recalculated historical entries in `docs/data/updates/updates_history.json` or ensure `updates_builder.py --rebuild-history` re-computes true deltas across known historical tags/snapshots.
   - Ensure the dropdown option labels in `docs/updates.js` render clear, accurate text: e.g. `${version} (${date}) — +${new_servers} servers, +${new_advisories} CVEs` (or total snapshot count if formatted as catalog total).
4. **Automated Testing**:
   - Add comprehensive tests in `tests/test_updates_builder_deltas.py` asserting:
     - SemVer sorting correctly orders `1.0.10` after `1.0.9` when descending.
     - Delta computation correctly calculates additions/updates between two synthetic catalogs.
     - `docs/updates.js` passes syntax validation (`node -c docs/updates.js`).

## Non-Interactive Completion Directive
Finalize all implementation, tests, and documentation directly. Run tests and commit with `[skip ci]`. Do not stop for open-ended questions.

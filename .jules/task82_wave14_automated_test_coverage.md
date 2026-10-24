# Task 82: Wave 14 Automated Test Coverage (P1)

**Defect:** W14-04 · **Files:** `tests/test_analytics.py`, `tests/test_wave14_portal.py` · **Wave:** 15 (after Tasks 78–81)

## Problem
Task 75 contracted `tests/test_analytics.py`, which does not exist. No tests cover Wave 14 frontend structure or the new pipeline fields.

## Required Change
1. `tests/test_analytics.py` (fixture-driven, calling the site builder on a tiny temp dataset):
   - `patched_remediable_count` / `zero_day_unpatched_count` correctness.
   - Capability surface counts (fs / shell / network / mutating / read-only).
   - Secrets perimeter + transport topology + tool shadowing aggregation.
   - Latest-version selection (Task 81).
   - `composite_risk_tier` / `highest_cve_severity` in catalog index (Task 79).
2. `tests/test_wave14_portal.py` (static checks, no browser):
   - `docs/index.html` contains config audit zone, primitive sub-tabs; `docs/updates.html` contains `historical-sparkline`, change-type chips, feed links.
   - `docs/app.js` / `docs/updates.js` pass `node -c` when `node` is available (skip otherwise).
   - Regression guard: `applyAdvisoryFilters` body does not reference `server.` (Task 78).

## Acceptance Criteria
- [ ] New tests pass locally and in CI (Python 3.12 & 3.14).
- [ ] Total suite: 346+N passed, 0 failed.
- [ ] No network access in tests.

## Constraints
No Playwright. Non-interactive completion.

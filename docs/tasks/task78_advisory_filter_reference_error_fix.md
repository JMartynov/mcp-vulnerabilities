# Task 78: Advisory Filter `ReferenceError` Fix (P0)

**Defect:** W14-01 · **File:** `docs/app.js` · **Wave:** 15

## Problem
`applyAdvisoryFilters()` (~L1301–1303) references an undefined `server` variable inside an advisory filter callback (param `adv`):
```js
if (el.filterToolsOnly && el.filterToolsOnly.checked) {
  if (!server.tools_count || server.tools_count === 0) return false;
}
```
With "Has Tools Only" checked, filtering advisories throws `ReferenceError: server is not defined`.

## Required Change
Replace the check with an advisory-scoped predicate: keep advisories whose `affected[*].database_specific.vulnerable_tools` is a non-empty array (or `adv.database_specific.vulnerable_tools`). Do **not** touch the server filter at ~L662 (there `server` is defined).

## Acceptance Criteria
- [ ] No `server` reference inside `applyAdvisoryFilters()`.
- [ ] Checking "Has Tools Only" on the Advisories tab filters to advisories with ≥1 vulnerable tool; no console errors.
- [ ] Unchecking restores the full list.
- [ ] `node -c docs/app.js` passes; `.venv/bin/pytest -q` no regressions.

## Constraints
Minimal diff; no unrelated refactors; keep existing comments. Non-interactive: finalize without asking open questions.

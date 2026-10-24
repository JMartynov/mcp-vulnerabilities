# Task 78: Advisory Filter `ReferenceError` Fix & Vulnerable Tools Predicate (P0)

**Defect Reference:** `DEFECT-W14-01` ([`docs/reports/code_review_wave14_portal_and_analytics.md`](../reports/code_review_wave14_portal_and_analytics.md))  
**Target Wave:** Wave 15A (Wave 14 Code Review Remediation)  
**Priority:** `P0` (Critical Runtime Crash Fix)

---

## 1. Architectural Context & Technical Objective

In `docs/app.js` (~lines 1286–1318), `applyAdvisoryFilters()` filters `allAdvisories` for the Security Advisories tab (`#advisories-view`). Inside the callback `allAdvisories.filter((adv) => { ... })`, lines 1301–1303 contain a copy-paste defect from `applyDirectoryFilters()`:

```javascript
// Has Tools Only Filter
if (el.filterToolsOnly && el.filterToolsOnly.checked) {
  if (!server.tools_count || server.tools_count === 0) return false;
}
```

Because `server` is not defined inside `applyAdvisoryFilters()` (the callback parameter is `adv`), checking the **"Only Servers with Tools"** (`#filterToolsOnly`) checkbox and switching to or filtering the Advisories tab throws an uncaught `ReferenceError: server is not defined`, halting JavaScript execution on the page.

This task replaces the invalid `server.tools_count` reference in `applyAdvisoryFilters()` with a dedicated advisory-scoped predicate `advisoryHasVulnerableTools(adv)` while preserving the valid `server.tools_count` check in `applyDirectoryFilters()` (~line 662).

---

## 2. Target Files & Isolation Boundaries

- **Primary File:** `docs/app.js`
- **Do NOT Modify:** `applyDirectoryFilters()` (~line 662) where `server` is legitimately in scope, or unrelated backend Python modules.

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Advisory-Scoped Vulnerable Tools Predicate (`INVARIANT_78_1A`)
- **Preconditions**: User checks `#filterToolsOnly` (`el.filterToolsOnly.checked === true`) and triggers `applyAdvisoryFilters()`.
- **Invariants**:
  - [ ] **INVARIANT_78_1A (Zero `ReferenceError`)**: `applyAdvisoryFilters()` executes with zero uncaught exceptions and contains no reference to `server`.
  - [ ] **INVARIANT_78_1B (Vulnerable Tools Filtering)**: Advisories are retained when `#filterToolsOnly` is checked if and only if:
    1. `Array.isArray(adv.database_specific?.vulnerable_tools) && adv.database_specific.vulnerable_tools.length > 0`, OR
    2. `Array.isArray(adv.affected)` and at least one `aff` entry has `Array.isArray(aff.database_specific?.vulnerable_tools) && aff.database_specific.vulnerable_tools.length > 0`.
  - [ ] **INVARIANT_78_1C (Filter Reset Parity)**: Unchecking `#filterToolsOnly` restores the full advisory list matching the active severity, ecosystem, and search filters.

### Scenario 2: Cross-Tab Filter Synchronization (`INVARIANT_78_2A`)
- **Preconditions**: User toggles `#filterToolsOnly`.
- **Invariants**:
  - [ ] **INVARIANT_78_2A (Event Listener Continuity)**: Toggling `#filterToolsOnly` refreshes `applyDirectoryFilters()` (and `applyAdvisoryFilters()` if `allAdvisories.length > 0`) without throwing errors.

---

## 4. Concrete Implementation Instructions

1. In `docs/app.js`, define helper `advisoryHasVulnerableTools(adv)`:
   ```javascript
   function advisoryHasVulnerableTools(adv) {
     if (Array.isArray(adv.database_specific?.vulnerable_tools) && adv.database_specific.vulnerable_tools.length > 0) {
       return true;
     }
     if (Array.isArray(adv.affected)) {
       return adv.affected.some(
         (aff) => Array.isArray(aff.database_specific?.vulnerable_tools) && aff.database_specific.vulnerable_tools.length > 0
       );
     }
     return false;
   }
   ```
2. In `applyAdvisoryFilters()` (`docs/app.js` ~lines 1301–1303), replace:
   ```javascript
   if (el.filterToolsOnly && el.filterToolsOnly.checked) {
     if (!server.tools_count || server.tools_count === 0) return false;
   }
   ```
   with:
   ```javascript
   if (el.filterToolsOnly && el.filterToolsOnly.checked) {
     if (!advisoryHasVulnerableTools(adv)) return false;
   }
   ```
3. Verify syntax via `node -c docs/app.js` and run `.venv/bin/pytest -q`.

---

## 5. Non-Interactive Completion Directive

Complete all implementation steps, verify all invariants locally, and commit directly without asking open-ended questions so the session cleanly transitions to `Completed`.

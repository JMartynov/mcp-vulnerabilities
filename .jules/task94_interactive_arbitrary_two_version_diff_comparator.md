# Task 94: Interactive Arbitrary Two-Version Diff Comparator in Modal (P2)

**Subsystem:** Front-End Modal (`docs/app.js`, `docs/updates.js`, `docs/style.css`)  
**Priority:** `P2`  
**Parent Plan:** [IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md](IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md)

---

## 1. Objective & Problem Statement
Currently in `#server-modal`, tool and version deltas only show changes relative to the immediate prior version in the array (`v[i]` vs `v[i-1]`). In enterprise patch management, security engineers frequently need to evaluate the delta between their currently deployed version (e.g. `v0.2.0`) and the latest patched release (e.g. `v1.5.0`), spanning multiple releases. Adding an arbitrary baseline version selector empowers teams to assess exact tool additions, parameter deprecations, and fixed CVEs across any version range.

---

## 2. Detailed Technical Requirements

### 2.1 Baseline Version Selector Control
1. In `#server-modal` above the primitive tabs, add a comparison toolbar:
   ```html
   <div class="version-comparator-toolbar">
     <label for="compare-base-select">Compare version <strong id="current-compare-version">v...</strong> against baseline:</label>
     <select id="compare-base-select" class="form-select form-select-sm">
       <option value="prev">Previous Version (default)</option>
       <!-- Populated with other available versions -->
     </select>
   </div>
   ```

### 2.2 Dynamic Multi-Version Diff Generator (`docs/app.js` & `docs/updates.js`)
1. In `renderTools(targetVersion, baseVersion)`:
   - Allow user to pick any arbitrary `baseVersion` from the dropdown.
   - Calculate added tools (`tools in target but not in base`).
   - Calculate removed tools (`tools in base but not in target`).
   - Calculate modified tools (same name but differing `canonical_hash` or parameter count).
   - Calculate resolved CVEs (advisories present in `base` that are fixed/absent in `target`).
   - Calculate newly introduced CVEs (if any).
2. Render clear color-coded diff summary:
   - `+ N Added Tools` (Green pill)
   - `- N Removed Tools` (Red pill)
   - `Δ N Modified Parameters` (Yellow pill)
   - `🛡️ N Fixed Vulnerabilities` (Emerald pill)
3. Fingerprint evolution badge:
   - Displays `sha256:<base_hash> ➔ sha256:<target_hash>`.

---

## 3. Acceptance Criteria
- [ ] Baseline version dropdown lists all alternate versions of the inspected server.
- [ ] Selecting an arbitrary older version computes the cumulative tool additions, removals, and parameter modifications.
- [ ] Fixed vulnerabilities between the two versions are highlighted in the diff summary.
- [ ] Switching versions or servers cleanly resets the comparator state.
- [ ] `node -c docs/app.js` and `node -c docs/updates.js` pass with zero syntax errors.

---

## 4. Operational Directives
- **Non-Interactive Completion Directive:** Complete implementation autonomously.
- **Safety Invariant:** Handle single-version packages gracefully (disabling comparator if only 1 version exists).

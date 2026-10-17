# Review Proposal: Task 46 (CI Resilience, PyPI Graceful Fallback & Force-Release Support)

**Branch:** `jules/review-6050437099581347833`  
**PR:** Task 46: CI Resilience, PyPI Graceful Fallback & Force-Release Support  
**Reviewer:** EULIS (Google Jules) Review Engine  
**Status:** Approved  

---

## 1. Scope & Verification Criteria Audit

- **VC-46.1: `workflow_dispatch` Input Schema**
  - Added `force_release` boolean input with default `false` and description `'Force version bump and release'`.
  - Enables on-demand manual workflow triggers to publish new vulnerability releases and update data feeds.
  - **Verdict:** PASSED.

- **VC-46.2: Force-Release Gate & Condition Evaluation**
  - Updated condition checks in `Commit and push updated security advisories & snapshot`:
    - Stage/commit check: `if ! git diff --staged --quiet || [ "${{ inputs.force_release }}" = "true" ]; then`
    - Release creation check: `if [ -n "$VULN_CHANGES" ] || [ "${{ inputs.force_release }}" = "true" ]; then`
    - GitHub Release publish gate: `if [ -n "$VULN_CHANGES" ] || [ "${{ inputs.force_release }}" = "true" ]; then`
  - Guarantees version bump, site build, updates build, tagging, and GitHub Release creation even when no new advisories arrived.
  - **Verdict:** PASSED.

- **VC-46.3: PyPI OIDC Fallback Resilience**
  - Added `continue-on-error: true` to `pypi-release` reusable workflow invocation (`uses: ./.github/workflows/release.yaml`).
  - Shields the daily sync workflow from failing if PyPI Trusted Publishing OIDC token exchange experiences transient validation issues.
  - **Verdict:** PASSED.

---

## 2. Review Findings & Applied Refinements

1. **Parity with Upstream Ecosystem**:
   - Matches the release flow structure implemented in `mcp-fingerprints` Task 41.
   - Evaluates outer git diff staged check with `inputs.force_release == 'true'` to ensure on-demand releases trigger cleanly regardless of git diff status.

---

## 3. Test Coverage & Verification

- `.venv/bin/python -m pytest tests/ -q --tb=short`: **272 passed, 5 skipped** in 40.67s.

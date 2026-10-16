# Task 42: Automated Sync Delta Detection, Version Bumper (bump_version.py) & PyPI Release Pipeline (P0)

## 1. Architectural Context & Technical Objective
Implement automated sync delta detection (`src/mcp_vulnerabilities/delta_detector.py`) to identify substantive security data updates (new CVE/GHSA advisories, newly vulnerable package versions, or updated risk assessments). Create a standalone version bumper script (`scripts/bump_version.py`) that calculates semantic version increments (patch for data updates, minor for features) and updates `pyproject.toml` and `src/mcp_vulnerabilities/__init__.py`. Harden `.github/workflows/release.yml` to automate PyPI publishing via OIDC trusted publishing upon delta detection.

## 2. Target Files & Documentation to Update
- `scripts/bump_version.py`
- `src/mcp_vulnerabilities/delta_detector.py`
- `.github/workflows/release.yml`
- `tests/test_bump_version.py`
- `tests/test_delta_detector.py`
- `docs/release_pipeline.md`

## 3. EULIS Implementation & Branch Review Workflow
- Branch: `jules/review-task42`
- Implementation PR: `jules-gate pr --skip-ci`
- Offload Mode 2 EULIS Code Review: `jules-gate review-branch`
- Review verification: check `docs/reviews/review_task42.md`
- Test verification: run test suite via isolated subagent (`jules-gate verify`)
- Merge: `jules-gate pr-merge --skip-ci`

## 4. Acceptance & Verification Criteria
- [ ] `DeltaDetector` evaluates new advisories, version changes, and severity updates.
- [ ] `scripts/bump_version.py` bumps semver cleanly across `pyproject.toml` and `__init__.py`.
- [ ] Tagging and release workflow triggers only when delta thresholds are met.
- [ ] PyPI OIDC release workflow verified with dry-run and release test suites.
- [ ] Unit tests verify correct semver calculations across all delta scenarios.

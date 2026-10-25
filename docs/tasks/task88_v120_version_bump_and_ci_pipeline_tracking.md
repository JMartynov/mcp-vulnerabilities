# Task 88: Version Bump (`v1.2.0`), Portal Index Sync & CI/CD Pipeline Tracking (P0)

**Target Wave:** Wave 17B (Release Engineering & CI/CD Verification)  
**Priority:** `P0` (Release Gate)  
**Master Plan:** [`docs/tasks/IMPLEMENTATION_PLAN_WAVE17_CODE_REVIEW_DOCS_AND_RELEASE_V120.md`](IMPLEMENTATION_PLAN_WAVE17_CODE_REVIEW_DOCS_AND_RELEASE_V120.md)

---

## 1. Architectural Context & Technical Objective

After Tasks 86 and 87 complete the Wave 15/16 code review audit and v1.2.0 documentation synchronization, this task executes the `v1.2.0` version bump across the package metadata, backfills `highest_cve_severity` and `composite_risk_tier` in `docs/data/mcp_catalog_index.json` so the live GitHub Pages portal immediately reflects Task 79's composite risk badges, runs the full local test suite, pushes the release commit (without `[skip ci]`) to trigger GitHub Actions CI, and tracks the CI pipeline to 100% green completion.

---

## 2. Target Files & Isolation Boundaries

- **Primary Files:**
  - `pyproject.toml` (`version = "1.2.0"`)
  - `src/mcp_vulnerabilities/__init__.py` (`__version__ = "1.2.0"`)
  - `docs/data/mcp_catalog_index.json` (ensure `highest_cve_severity` and `composite_risk_tier` are populated on every entry)
  - Any test file asserting exact `__version__` if present

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Package Version Consistency (`INVARIANT_88_1A`)
- **Invariants**:
  - [ ] **INVARIANT_88_1A**: `pyproject.toml` `version` and `mcp_vulnerabilities.__version__` both equal `"1.2.0"`, and `mcp-vuln --version` (or python import check) reports `1.2.0`.

### Scenario 2: Live Static Portal Index Backfill (`INVARIANT_88_2A`)
- **Invariants**:
  - [ ] **INVARIANT_88_2A**: Every entry in `docs/data/mcp_catalog_index.json` contains `highest_cve_severity` and `composite_risk_tier` computed via `_compute_composite_risk` and cross-referenced against `docs/data/vulnerabilities.json`.

### Scenario 3: Full Local Pytest & Remote GitHub Actions CI (`INVARIANT_88_3A` – `INVARIANT_88_3B`)
- **Invariants**:
  - [ ] **INVARIANT_88_3A**: `.venv/bin/pytest -q` passes with 0 failures locally.
  - [ ] **INVARIANT_88_3B**: GitHub Actions `CI` workflow (`ci.yml`) triggers on `main` and passes 100% across Python 3.12 and Python 3.14 matrix jobs.

---

## 4. Concrete Implementation Instructions

1. Update `version = "1.2.0"` in `pyproject.toml` and `__version__ = "1.2.0"` in `src/mcp_vulnerabilities/__init__.py`.
2. Run a deterministic Python script using `src/mcp_vulnerabilities/site_builder.py` helpers (`_compute_composite_risk`) and `docs/data/vulnerabilities.json` to ensure every server entry in `docs/data/mcp_catalog_index.json` has accurate `highest_cve_severity` and `composite_risk_tier` fields.
3. Run `.venv/bin/pytest -q` and `node -c docs/app.js && node -c docs/updates.js` to verify 0 regressions.
4. Commit with `release: bump version to v1.2.0 and sync portal catalog index` (WITHOUT `[skip ci]`), push to `origin main`, and track `gh run list --limit 1` / `gh run watch` until CI passes 100%.

---

## 5. Non-Interactive Completion Directive

Complete all steps, verify all tests pass locally, and commit directly without asking open-ended questions so the session cleanly transitions to `Completed`.

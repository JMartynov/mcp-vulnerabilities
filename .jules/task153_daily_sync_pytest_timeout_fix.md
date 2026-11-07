# Task 153: Daily Sync CI Pytest-Timeout Dependency & Workflow Resilience Fix (P0)

**Target Wave:** Wave 28 (Runtime Edge Cases, Subsystems & CI Resilience)  
**Priority:** `P0` (Critical - Resolves exit code 4 error in `daily_sync.yml`)  
**Status:** `In Progress`  

---

## 1. Architectural Context & Technical Objective

Workflow `.github/workflows/daily_sync.yml` failed with exit code 4 during step `Validate OSV Dataset Integrity & Schemas`:
```
pytest: error: unrecognized arguments: --timeout=60
```
`pytest-timeout` is missing from `[project.optional-dependencies] dev` in `pyproject.toml`, causing `--timeout=60` to fail in CI environments where `pytest-timeout` is not pre-installed.

---

## 2. Invariant Specifications

- **INVARIANT_153_1 (Pytest-Timeout Dependency)**:
  Add `"pytest-timeout>=2.2.0"` to `[project.optional-dependencies] dev` in `pyproject.toml`.
- **INVARIANT_153_2 (Workflow Resilience)**:
  In `.github/workflows/daily_sync.yml`, ensure step `Install dependencies` installs `pytest-timeout`.
- **INVARIANT_153_3 (Verification Parity)**:
  Run `pytest -v --timeout=60 tests/test_documentation_parity.py` to confirm flag validity.

---

## 3. Target Files

- `pyproject.toml`
- `.github/workflows/daily_sync.yml`
- `docs/tasks/README.md`

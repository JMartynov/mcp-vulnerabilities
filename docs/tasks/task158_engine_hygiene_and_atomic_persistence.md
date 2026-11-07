# Task 158: Engine Hygiene, Asyncio Loop Scoping, and Universal Atomic Persistence

## Status: IN PROGRESS
**Priority:** P0 (Highest)  
**Components:** Test Infrastructure, Pytest Configuration, Atomic State Persistence  
**Target Files:**
- `pyproject.toml`
- `tests/test_trivy_engine.py`
- `src/mcp_vulnerabilities/catalog_state.py`
- `src/mcp_vulnerabilities/drift/engine.py`

---

## 1. Objectives & Scope

1. **Pytest-Asyncio Loop Scoping:**
   - Eliminate `PytestDeprecationWarning: The configuration option "asyncio_default_fixture_loop_scope" is unset` by explicitly configuring `asyncio_default_fixture_loop_scope = "function"` under `[tool.pytest.ini_options]` in `pyproject.toml`.
2. **Synthetic Trivy Mock Fallback:**
   - In `tests/test_trivy_engine.py`, replace `@pytest.mark.skipif(shutil.which("trivy") is None)` with a synthetic subprocess runner fixture when the native binary is missing, ensuring 100% of test suites execute across all developer OS environments (0 skipped tests).
3. **Universal Atomic State Persistence:**
   - Propagate `atomic_save_json` from `src/mcp_vulnerabilities/state.py` into `catalog_state.py` and `drift/engine.py` to prevent partial file writes, state corruption, or truncated JSON during unexpected shutdown.

---

## 2. Acceptance Criteria

- [ ] `pytest -q` runs with **0 deprecation warnings**.
- [ ] `tests/test_trivy_engine.py` passes 100% without skips even when `trivy` is not installed in PATH.
- [ ] `McpCatalogState.save()` and `DriftEngine` persist state via atomic temporary files with `.bak` recovery.
- [ ] 100% tests pass across the entire repository.

### Task: Implement Acceptance Test Suite for PyPI Version Resolution & Cache Invalidation

#### 1. Context & Contract:
Create a dedicated end-to-end acceptance test file: `tests/test_acceptance_pypi_versioning.py`.
It must verify the real-world PyPI version resolution, semver re-audit invalidation, and catalog state management:
1. `test_live_pypi_json_version_resolution()`:
   - Test `PypiDiscoveryProvider.resolve_package_version()` against live/mocked PyPI JSON endpoints (`https://pypi.org/pypi/{name}/json`) for real MCP servers like `fastmcp`, `mcp`, `mcp-server-git`.
   - Verify valid semver string is returned and graceful error handling on nonexistent packages.
2. `test_pypi_semver_bump_triggers_re_audit()`:
   - Pre-seed `McpCatalogState` with version `0.4.0` for a package.
   - Assert `should_query("PyPI", "fastmcp", "0.4.0")` returns `False` (warm cache).
   - Simulate a new release version `0.4.1` and assert `should_query("PyPI", "fastmcp", "0.4.1")` returns `True`.
3. `test_bulk_discovery_does_not_rate_limit_pypi()`:
   - Verify that `PypiDiscoveryProvider.discover(resolve_versions=False)` returns discovered packages immediately without triggering hundreds of individual HTTP requests.

#### 2. Strict Guardrails:
- Must follow standard pytest / unittest conventions.
- All tests must execute cleanly and quickly.
- All tests must pass with `pytest`.

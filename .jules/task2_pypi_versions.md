### Task: Implement PyPI Package Version Resolution & Semver Re-Audit Invalidation

#### 1. Context & Contract:
In `src/mcp_vulnerabilities/discovery/pypi.py` and `src/mcp_vulnerabilities/catalog.py`:
1. In `src/mcp_vulnerabilities/discovery/pypi.py`:
   - Currently, `version: ""` is hardcoded because PEP 691 `/simple/` root index does not supply versions.
   - Add a method `resolve_package_version(name: str, timeout: float = 5.0) -> str` that queries `https://pypi.org/pypi/{name}/json` and extracts `info.version`.
   - Ensure versions can be populated or enriched so that `normalize_version()` can detect version changes.
2. In `src/mcp_vulnerabilities/catalog.py`:
   - In `McpCatalogState.should_query()`:
     If `current_version` is provided or if `record.last_version_seen` is empty, ensure it triggers an audit.
   - In `update_record()`:
     Ensure normalized version is persisted correctly.

#### 2. Strict Guardrails:
- Zero unauthorized external dependencies.
- Ensure timeout and graceful error handling on network requests.

#### 3. Testing:
- Add tests in `tests/test_catalog_state.py` asserting version change detection on PyPI and npm packages.
- All tests must pass with `pytest`.

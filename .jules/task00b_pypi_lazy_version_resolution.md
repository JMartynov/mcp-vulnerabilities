### Task: PyPI Lazy Version Resolution & Version Cache Invalidation (Foundational 00-B)

#### 1. Architectural Context & Purpose:
During discovery of MCP servers from Python's package index (PyPI), query responses from the PEP 691 `/simple/` root endpoint return package names without release versions (`version: ""`). When version information is blank or unpinned, vulnerability matching cannot accurately evaluate semver range specifications (`RangeSpec`), resulting in either false negatives or false positives across the search index.
This task implements lazy resolution against the PyPI JSON API (`/pypi/<package>/json`), extracting canonical release versions and maintaining a cache with automatic invalidation upon upstream package publication.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/discovery/pypi.py`: Class `PypiDiscoveryProvider` and method `resolve_package_version()`.
* `src/mcp_vulnerabilities/catalog_state.py`: Class `CatalogStateManager` caching version lookups in `data/mcp_catalog_state.json`.
* `tests/test_acceptance_pypi_versioning.py`: Acceptance test suite verifying lazy resolution and cache expiration.

#### 3. Engineering & Implementation Blueprint:
1. **Lazy Version Resolution**:
   - When a discovered server record has an empty `version` field, query `https://pypi.org/pypi/{package}/json`.
   - Parse `info.version` from the JSON response and update the `DiscoveredServer` record.
2. **Persistent Cache & Invalidation**:
   - Cache resolved versions in `data/mcp_catalog_state.json` with a TTL (e.g. 7 days).
   - Invalidate cache entries when a new release tag or advisory is reported for the package.
3. **Graceful Fallback & Error Handling**:
   - Catch `HTTPError` 404/500 and network timeouts; fallback to unpinned state with a warning rather than crashing discovery.
4. **Acceptance Test Suite**:
   - Create `tests/test_acceptance_pypi_versioning.py` verifying that unversioned packages receive valid semver strings and cached records avoid duplicate network requests.

#### 4. Guardrails & Security Invariants:
* **Deterministic Versioning**: All version strings must adhere to PEP 440 / SemVer specifications.
* **Network Isolation**: Cached state must be queried before issuing outbound HTTP requests.

#### 5. Acceptance Criteria:
- [x] PyPI discovery lazily queries `/pypi/<package>/json` for packages with missing versions.
- [x] Canonical versions are persisted to `data/mcp_servers.json` and cached in `data/mcp_catalog_state.json`.
- [x] Network failures or missing packages fallback safely without halting the discovery pipeline.
- [x] Acceptance tests in `tests/test_acceptance_pypi_versioning.py` pass with 100% assertions satisfied.

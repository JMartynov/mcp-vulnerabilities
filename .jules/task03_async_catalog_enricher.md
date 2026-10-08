### Task: Asynchronous Catalog Version Enrichment Engine

#### 1. Architectural Context & Problem Analysis:
The MCP Server Catalog ([`data/mcp_servers.json`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/data/mcp_servers.json)) maintains intelligence on **11,506 MCP servers** across multiple package registries.
During multi-registry discovery:
* PyPI discovery queries PEP 691 JSON Simple Index (`https://pypi.org/simple/`), identifying 6,068 MCP server packages.
* However, PEP 691 root endpoints only expose project names without versions. To maintain sub-second crawler performance, `version: ""` was set as a placeholder.
* Under [`McpCatalogState.should_query()`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/catalog.py), version delta checks compare `normalize_version(current_version)` against `last_version_seen`. Because `version` is empty, packages cannot trigger version-bump invalidations and fall back to the 30-day TTL expiry.

An asynchronous, rate-limited batch enricher is required to backfill versions in `data/mcp_servers.json` without blocking the primary fast discovery pass.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/discovery/pypi.py`: `resolve_package_version()` (lines 69–85).
* `src/mcp_vulnerabilities/discovery/orchestrator.py`: `McpDiscoveryOrchestrator` and catalog storage.
* `src/mcp_vulnerabilities/catalog.py`: `McpCatalogState` tracking audited versions.
* `src/mcp_vulnerabilities/cli.py`: Subcommand interface.
* `data/mcp_servers.json`: Target persistent catalog.

#### 3. Engineering & Implementation Blueprint:
1. Create `src/mcp_vulnerabilities/discovery/enricher.py`:
   - Class `CatalogVersionEnricher`:
     - Load `data/mcp_servers.json`.
     - Filter candidate packages where `ecosystem == "PyPI"` and `version == ""`.
     - Dispatch concurrent lookups via `concurrent.futures.ThreadPoolExecutor(max_workers=workers)`:
       Calls `PypiDiscoveryProvider.resolve_package_version(name, timeout=3.0)`.
     - Support configurable CLI parameters: `--limit <N>` (e.g. 200 items per sweep) and `--workers <W>` (default 10).
     - Atomically save updated catalog to `data/mcp_servers.json` using temporary file replacement (`os.replace`).
2. Update `src/mcp_vulnerabilities/cli.py`:
   - Add subcommand `enrich`:
     ```bash
     python -m mcp_vulnerabilities.cli enrich --catalog-file data/mcp_servers.json --limit 200 --workers 10
     ```
   - Provide real-time logging of progress: `Enriched X/Y packages (Z updated, W failed/skipped)`.

#### 4. Guardrails & Reliability Invariants:
* **Network Resilience**: Handle HTTP 404 (removed/unpublished packages), timeouts, and rate limits gracefully; never crash the overall enrichment sweep on individual failures.
* **Atomic File Replacement**: Write to a temporary file (`.tmp`) and replace atomically to prevent file corruption if the process is terminated mid-flight.
* **Cache Safety**: Do not overwrite existing non-empty versions unless explicitly flagged with `--force`.

#### 5. Acceptance Criteria & Test Plan:
- [ ] Running `python -m mcp_vulnerabilities.cli enrich --limit 20 --workers 5` enriches versions in `data/mcp_servers.json`.
- [ ] Enriched entries have valid semver strings in `data/mcp_servers.json`.
- [ ] Unit test in `tests/test_discovery_providers.py` verifies `CatalogVersionEnricher` concurrency, timeout handling, and atomic writes using mock responses.
- [ ] Enriched versions successfully trigger `McpCatalogState.should_query() == True` when a higher version is supplied.
- [ ] 100% of existing tests pass (`pytest -v`).

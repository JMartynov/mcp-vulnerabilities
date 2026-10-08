### Task: Asynchronous Catalog Version Enrichment Engine

#### 1. Overview & Context:
Bulk discovery from PyPI PEP 691 (`https://pypi.org/simple/`) cataloged over 6,000 MCP servers, but set `version: ""` to avoid thousands of blocking sequential network calls. We now need a concurrent batch enrichment engine to resolve versions from PyPI JSON endpoints (`https://pypi.org/pypi/{name}/json`) asynchronously and update `data/mcp_servers.json`.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/discovery/pypi.py`: `resolve_package_version()` (lines 69–85).
* `src/mcp_vulnerabilities/discovery/orchestrator.py`: `McpDiscoveryOrchestrator` and catalog storage.
* `src/mcp_vulnerabilities/cli.py`: Subcommand interface.
* `data/mcp_servers.json`: Target catalog file.

#### 3. Implementation Details:
1. Create `src/mcp_vulnerabilities/discovery/enricher.py`:
   - Class `CatalogVersionEnricher`:
     - Loads `catalog_file` (`data/mcp_servers.json`).
     - Filters servers where `ecosystem == "PyPI"` and `version == ""`.
     - Uses `concurrent.futures.ThreadPoolExecutor(max_workers=workers)` to call `PypiDiscoveryProvider.resolve_package_version(name)` concurrently.
     - Supports `--limit N` (e.g., 200 items per batch) to avoid network congestion.
     - Atomically writes updated records to `data/mcp_servers.json`.
2. In `src/mcp_vulnerabilities/cli.py`:
   - Add CLI subcommand `enrich`:
     ```python
     enrich_p = subparsers.add_parser("enrich", help="Asynchronously enrich package versions in servers catalog")
     enrich_p.add_argument("--catalog-file", default="data/mcp_servers.json")
     enrich_p.add_argument("--limit", type=int, default=200, help="Max packages to enrich")
     enrich_p.add_argument("--workers", type=int, default=10, help="Concurrent worker threads")
     ```

#### 4. Strict Guardrails:
- Must handle 404s, timeouts, or network exceptions gracefully without failing the entire batch.
- Must perform atomic writes via temporary file replacement (`os.replace`) to prevent file corruption.

#### 5. Acceptance Criteria & Tests:
- [ ] Running `python -m mcp_vulnerabilities.cli enrich --limit 10 --workers 5` resolves versions and updates `data/mcp_servers.json`.
- [ ] Unit tests in `tests/test_discovery_providers.py` or new `tests/test_catalog_enricher.py` verify concurrency, timeout handling, and atomic updates.
- [ ] All tests pass with `pytest`.

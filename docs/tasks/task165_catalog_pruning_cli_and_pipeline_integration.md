# Task 165: Catalog Pruning CLI and Ingestion Pipeline Integration

## Objective
Add `--prune`, `--prune-archived`, and `--prune-deleted` flags to `mcp-vuln sync` and `discover`, connecting dead-repository and tombstone pruning directly into `McpVulnerabilityPipeline` and `McpCatalogState`.

## Background & Issues Identified
- `McpCatalogState` in `catalog.py` supports tombstones and `GitHubCuratedDiscoveryProvider.is_repository_archived_or_pruned` detects 404/410/archived repos, but `cli.py` has no CLI pruning flags.
- `McpVulnerabilityPipeline` runs batch vulnerability sync without triggering dead repository pruning or catalog cleanup.

## Scope of Changes
1. `src/mcp_vulnerabilities/cli.py`:
   - Add `--prune`, `--prune-archived`, `--prune-deleted`, and `--offline-backoff` arguments to `sync` and `discover` subparsers.
2. `src/mcp_vulnerabilities/pipeline.py`:
   - In `McpVulnerabilityPipeline.run()`, if `include_pruning` is enabled, verify candidate servers against repository status and mark tombstones in `catalog_state`.
3. `src/mcp_vulnerabilities/catalog.py`:
   - Add `prune_catalog(catalog_data: dict, catalog_state: McpCatalogState) -> dict` to filter out tombstoned or archived servers.
4. `tests/test_catalog_pruning_and_backoff.py`:
   - Add CLI integration tests verifying `mcp-vuln sync --prune` and `mcp-vuln discover --prune`.

## Acceptance Criteria
- `mcp-vuln sync --help` documents `--prune` and `--prune-archived` flags.
- Pipeline accurately records tombstones and purges deleted/archived entries when `--prune` is passed.
- `pytest tests/test_catalog_pruning_and_backoff.py` passes 100%.

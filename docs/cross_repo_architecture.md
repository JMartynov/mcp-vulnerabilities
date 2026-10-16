# Cross-Repository Synchronization Architecture

## Overview

The `mcp-vulnerabilities` platform maintains an automated, cross-repository synchronization channel with the `mcp-fingerprints` repository. This channel ensures that structural knowledge regarding multi-server configurations, capability fingerprints, and canonical package definitions (`passports.json.gz`) are seamlessly ingested and mapped against the vulnerability database.

## Architecture

1. **Daily Upstream Ingestion (`CrossRepoSyncManager`)**
   - The primary source of truth for MCP Server Passports is maintained within `mcp-fingerprints`.
   - The sync manager fetches the latest release asset `passports.json.gz` via the GitHub API (`/repos/jmartynov/mcp-fingerprints/releases/latest`).
   - If network rate limiting occurs (403), the manager gracefully falls back to the local repository snapshot (`data/passports.json.gz`).

2. **Cross-Repo Correlation Engine (`VulnerabilityCorrelator`)**
   - After the latest structural data is ingested, the engine executes `mcp-vuln correlate`.
   - This process iterates over all server versions in the `passports.json.gz` file and evaluates them against the active vulnerability database (`vulnerabilities.json.gz`).
   - The output binds OSV security advisories directly to granular version capabilities mapped within the passports.

3. **Workflow Pipelines**
   - `.github/workflows/daily_sync.yml`: Main scheduled action triggering upstream synchronization, multi-registry discovery, vulnerability syncing (NVD, GHSA), cross-repo correlation, site generation, and state persistence.
   - `.github/workflows/cross_repo_sync.yml`: Dedicated synchronization pipeline solely for integrating passports, compiling snapshots, and executing the full end-to-end integration test suite (`tests/test_e2e_cross_repo_sync.py`).

## Network Constraints & Airgapping

The synchronization mechanism relies on the GitHub REST API. For strict, air-gapped environments or restricted networks, the fallback mechanism retains a fully local operation by avoiding failure states and utilizing `data/passports.json.gz` directly. Enterprise deployments utilizing `export-airgap` bundles will inherently maintain offline integrity without requiring remote syncs.

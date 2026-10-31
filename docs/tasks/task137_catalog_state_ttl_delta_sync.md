# Task 137: Catalog State TTL Delta Sync, Cache Invalidation & Deprecation Pruning (P0)

**Subsystem:** Ingestion Pipeline & Catalog Cache Engine (`src/mcp_vulnerabilities/catalog.py`, `src/mcp_vulnerabilities/discovery/npm.py`, `src/mcp_vulnerabilities/discovery/pypi.py`, `src/mcp_vulnerabilities/discovery/github_curated.py`, `src/mcp_vulnerabilities/pipeline.py`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave24_empirical_remediation_and_feature_hardening.md](master_plan_wave24_empirical_remediation_and_feature_hardening.md)

---

## 1. Objective & Problem Statement

During the 300-item empirical traceability audit in Wave 23 (Track A), several data fidelity issues were identified in the ingestion pipeline:
1. **npm Deprecation Persistence**: Three real npm packages identified during the audit carried upstream deprecation notices (`deprecated: true` / deprecation message in npm registry metadata), yet persisted indefinitely in `data/mcp_catalog_state.json` and `docs/data/mcp_catalog_index.json` as active recommendations.
2. **PyPI Yanked Releases**: Several PyPI packages had yanked releases (`"yanked": true` in PEP 691 JSON), but these releases were erroneously evaluated as candidate `latest_version` or recommended remediation versions.
3. **GitHub Stale References**: Multiple GitHub repositories cataloged via curated Awesome lists had been archived (`isArchived: true`) or deleted (HTTP 404), yet lingered in the catalog due to lack of deletion pruning.
4. **Unbounded Cache Staleness**: `McpCatalogState` in `src/mcp_vulnerabilities/catalog.py` cached package records without an active TTL expiration or tombstone tracking mechanism, causing the system to either retain stale data indefinitely or incur redundant network queries on every run.

This task implements an intelligent **TTL Delta Synchronization, Cache Invalidation, and Deprecation Pruning Engine** across the discovery providers and catalog state manager.

---

## 2. Detailed Technical Requirements

### 2.1 `McpCatalogState` Enhancements (`src/mcp_vulnerabilities/catalog.py`)

1. **TTL Expiration Evaluation**:
   - Each `ServerRecord` in `McpCatalogState.records` tracks `last_checked_utc` (ISO 8601).
   - Implement `is_expired(key: str, ttl_days: int = 30) -> bool`: returns `True` if `last_checked_utc` is older than `ttl_days` or missing.
   - Refactor `should_query(ecosystem: str, name: str, current_version: str | None, ttl_days: int = 30) -> bool`:
     - Returns `True` if record does not exist.
     - Returns `True` if `current_version` is different from `last_version_seen` (semver delta).
     - Returns `True` if `is_expired(key, ttl_days)` is `True`.
     - Returns `False` otherwise (cache hit).
2. **Deprecation & Tombstone Pruning**:
   - Introduce `TombstoneRecord`:
     ```python
     @dataclass
     class TombstoneRecord:
         name: str
         ecosystem: str
         reason: str  # "deprecated", "yanked", "archived", "deleted_404"
         tombstoned_at_utc: str
         details: str = ""
     ```
   - Store tombstones in `self.tombstones: dict[str, TombstoneRecord]`.
   - Implement `record_deprecation(ecosystem: str, name: str, reason: str, details: str = "") -> None`:
     - Removes package from `self.records`.
     - Records tombstone in `self.tombstones`.
     - Prunes record from the active catalog index during build.
3. **Corrupt State Recovery Invariant**:
   - Maintain the safe corruption recovery behavior: if loading `mcp_catalog_state.json` fails due to JSON syntax errors or partial writes, back it up to `mcp_catalog_state.json.corrupt.bak` and re-initialize clean empty state without crashing.

### 2.2 Discovery Provider Ingestion Hardening

#### 1. `npm.py` (`src/mcp_vulnerabilities/discovery/npm.py`)
- When fetching package metadata from `https://registry.npmjs.org/<pkg>`, inspect the latest document for the `"deprecated"` key.
- If `"deprecated"` is present (non-empty string or `True`), set `record.is_deprecated = True` and capture the deprecation message.
- Pass deprecation signals to `McpCatalogState.record_deprecation()`.

#### 2. `pypi.py` (`src/mcp_vulnerabilities/discovery/pypi.py`)
- In PEP 691 JSON resolution (`https://pypi.org/pypi/<pkg>/json`):
  - Inspect `releases[ver]` for `"yanked": true`.
  - Exclude yanked versions from `latest_version` resolution and safe upgrade recommendation calculations.
  - If all releases are yanked, treat package as deprecated.

#### 3. `github_curated.py` (`src/mcp_vulnerabilities/discovery/github_curated.py`)
- Handle repository status during URL normalization and metadata fetch:
  - On HTTP `404 Not Found` or `410 Gone`: record tombstone `reason="deleted_404"`.
  - On GitHub API `isArchived: true`: record tombstone `reason="archived"`.
  - Prune archived/deleted entries from returned candidates.

### 2.3 Pipeline Delta Synchronization (`src/mcp_vulnerabilities/pipeline.py`)

- Update `VulnerabilityPipeline.sync_all()`:
  - Integrate `should_query()` checks before dispatching OSV batch requests.
  - Automatically filter out tombstoned packages before compiling `docs/data/mcp_catalog_index.json`.
  - Save updated catalog state atomically to avoid corrupt state files on process termination.

---

## 3. Invariant Requirements & Verification Plan

### 3.1 Verification Invariants
1. **Deprecation Exclusion Invariant**:
   - Any package marked `deprecated` by npm registry or `archived` by GitHub must NOT appear in `docs/data/mcp_catalog_index.json` under active recommendations.
2. **Yanked Release Invariant**:
   - No version marked `"yanked": true` on PyPI may be stamped as `latest_version` in `mcp_catalog_index.json` or `passports.json.gz`.
3. **Monotonic Tombstone Invariant**:
   - Once a package is tombstoned, subsequent discovery iterations must not re-query upstream or resurrect the package unless explicitly un-deprecated upstream.
4. **State File Corruption Invariant**:
   - Injecting corrupted JSON into `mcp_catalog_state.json` must generate `mcp_catalog_state.json.corrupt.bak` and proceed with a clean state.

### 3.2 Automated Test Suite (`tests/test_catalog_ttl_delta_sync.py`)
Author a comprehensive unit and integration test suite asserting:
- `test_catalog_state_ttl_expiration`: records older than 30 days evaluate `is_expired() == True`.
- `test_catalog_state_semver_delta`: version change triggers `should_query() == True`.
- `test_npm_deprecation_pruning`: mock npm package with `deprecated: "Use @mcp/v2"` is tombstoned.
- `test_pypi_yanked_version_filtering`: yanked latest version falls back to previous non-yanked release.
- `test_github_archived_and_deleted_pruning`: 404 and archived repos are pruned from candidate list.
- `test_corrupt_state_recovery`: malformed state file is backed up and reinitialized.

---

## 4. Deliverables & Integration Checklist

- [ ] Implement `is_expired`, `TombstoneRecord`, `record_deprecation`, and tombstone persistence in `src/mcp_vulnerabilities/catalog.py`.
- [ ] Add deprecation detection to `src/mcp_vulnerabilities/discovery/npm.py`.
- [ ] Add yanked release filtering to `src/mcp_vulnerabilities/discovery/pypi.py`.
- [ ] Add 404 and archived repository pruning to `src/mcp_vulnerabilities/discovery/github_curated.py`.
- [ ] Connect delta sync and tombstone pruning in `src/mcp_vulnerabilities/pipeline.py`.
- [ ] Author and run `tests/test_catalog_ttl_delta_sync.py` verifying all invariants pass.

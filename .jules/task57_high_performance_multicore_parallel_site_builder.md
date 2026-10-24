# Task 57: High-Performance Multi-Core Parallel Site Builder & Two-Tier SHA Cache (P1)

## 1. Architectural Context & Technical Objective

When running `python -m mcp_vulnerabilities.site_builder`, the generator sequentially iterates over all 5,500+ server passports to:
1. Index and sort multi-version release histories.
2. Evaluate SemVer ranges across hundreds of OSV advisories.
3. Compute safe remediation upgrade targets and commands.
4. Serialize and shard datasets into 32 shard files (`shard_00.json` through `shard_1f.json`) plus `mcp_catalog_index.json`.

On multi-core workstations and CI runners, this single-threaded processing takes **40 to 60 seconds**, consuming valuable build minutes on every daily sync run.

In `mcp-fingerprints` (Task 46), a high-performance **two-tier SHA-256 cache engine** (`cache.py`) and **multi-core process pool batching** (`ProcessPoolExecutor`) were implemented to accelerate passport validation by 10x.

### Core Objectives:
1. Implement `src/mcp_vulnerabilities/cache.py`:
   - Two-tier disk cache (`.cache/mcp_vuln/` or `~/.cache/mcp-vulnerabilities/`):
     - Tier 1: In-memory LRU cache for active advisory evaluation.
     - Tier 2: Content-addressable SHA-256 disk cache keyed by `(passport_canonical_hash, osv_index_hash)`.
   - If neither the server passport nor the matching vulnerability advisories have changed, load the precomputed version vulnerability matrix and remediation metadata directly from cache.
2. Refactor `src/mcp_vulnerabilities/site_builder.py`:
   - Replace sequential loop with `ProcessPoolExecutor` / `ThreadPoolExecutor` parallel worker batching.
   - Partition servers into chunks across CPU cores (`os.cpu_count() or 4`).
   - Merge worker results into deterministic sharded datasets (`shard_00.json` - `shard_1f.json`) preserving identical output formatting.
3. Add CLI flags to `site_builder.py` and `mcp-vuln site-build`:
   - `--workers <N>`: Configurable worker concurrency (default: CPU count).
   - `--no-cache`: Force complete re-evaluation without cache.
   - `--benchmark`: Print detailed wall-clock and per-stage timing breakdown.
4. Accelerate site generation time to **under 8 seconds** (cold run) and **under 2 seconds** (cached run).

---

## 2. Target Files & Documentation
- `src/mcp_vulnerabilities/cache.py` (New module)
- `src/mcp_vulnerabilities/site_builder.py`
- `tests/test_parallel_site_builder.py`
- `docs/tasks/README.md`

---

## 3. Super Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Output Determinism & Shard Parity Invariant
- **Preconditions**: A test dataset containing 200 server passports and 50 OSV advisories.
- **Test Steps**:
  1. Build site shards sequentially with `--workers 1 --no-cache`.
  2. Build site shards in parallel with `--workers 4`.
  3. Compare all generated shard JSON files (`shard_*.json`) and `mcp_catalog_index.json`.
- **Invariants**:
  - [x] **INVARIANT_1A (Bit-for-Bit Determinism)**: The shard assignments (modulo 32 hash partition) and JSON keys MUST be identical between sequential and parallel runs.
  - [x] **INVARIANT_1B (Sort Order Parity)**: Servers within each shard MUST remain sorted alphabetically by `package_name`.

### Scenario 2: Two-Tier Cache Hit Invariant
- **Preconditions**: A built site with cache enabled.
- **Test Steps**:
  1. Run site builder to populate cache (Run 1).
  2. Run site builder immediately again without changes (Run 2).
- **Invariants**:
  - [x] **INVARIANT_2A (Cache Hit Rate)**: Run 2 MUST report $100\%$ cache hit rate on version evaluation.
  - [x] **INVARIANT_2B (Execution Speedup)**: Run 2 wall-clock time MUST be at least $4\times$ faster than Run 1.

### Scenario 3: Cache Invalidation Invariant
- **Preconditions**: Modify a single passport (e.g. bump version) or add a new OSV advisory.
- **Test Steps**:
  1. Run site builder.
- **Invariants**:
  - [x] **INVARIANT_3A (Targeted Invalidation)**: Only the modified server's cache entry is invalidated and re-evaluated.
  - [x] **INVARIANT_3B (Unmodified Reuse)**: All other unmodified servers reuse their cached version vulnerability matrices.

### Scenario 4: Worker Exception Resilience Invariant
- **Preconditions**: Introduce a corrupt passport entry into the processing queue.
- **Test Steps**:
  1. Run parallel site builder.
- **Invariants**:
  - [x] **INVARIANT_4A (Graceful Error Logging)**: The worker logs a clear warning for the corrupt server without crashing the process pool.
  - [x] **INVARIANT_4B (Complete Sharding)**: All remaining valid servers are successfully processed and written to shards.

---

## 4. Implementation Steps

1. Create `src/mcp_vulnerabilities/cache.py`:
   - Implement `TwoTierVulnerabilityCache` with SHA-256 content keying.
2. Refactor `src/mcp_vulnerabilities/site_builder.py`:
   - Implement `_process_server_batch(servers, matcher, cache)`.
   - Implement `build_site_parallel(passports_path, vuln_path, output_dir, workers, use_cache)`.
   - Update CLI argument parser with `--workers`, `--no-cache`, `--benchmark`.
3. Author test suite in `tests/test_parallel_site_builder.py`.
4. Verify `pytest -q tests/test_parallel_site_builder.py` passes 100%.

## Non-Interactive Completion Directive
Execute this task end-to-end without asking interactive questions. Implement `src/mcp_vulnerabilities/cache.py` and refactor `src/mcp_vulnerabilities/site_builder.py`. Add the comprehensive test suite in `tests/test_parallel_site_builder.py`, verify that all tests pass (`pytest -q`), and conclude directly with a complete patch so the remote environment cleanly transitions to `Completed`.

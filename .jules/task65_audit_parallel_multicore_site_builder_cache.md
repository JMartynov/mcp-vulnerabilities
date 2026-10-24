# Task 65: Empirical Audit — Parallel Multicore Site Builder & Cache Determinism (P0)

## 1. Architectural Context & Technical Objective

Generating the static security portal across 5,500+ MCP server packages requires multicore multiprocessing and aggressive disk caching (`site_builder.py`, `cache.py`). If the site builder introduces non-deterministic sorting across worker processes, crashes completely when an isolated worker encounters a malformed package, or retains stale vulnerability counts when cache keys fail to invalidate, the deployed web portal will present incorrect or flickering security data.

This task conducts an autonomous, live empirical audit of the parallel site builder across multicore execution counts, worker crash injection, bit-for-bit determinism checks, and cache invalidation scenarios, authors `tests/audit/test_audit_task65.py`, and publishes a comprehensive technical report to `docs/audit/audit_task65_site_builder_cache.md` categorizing all findings by **HIGH**, **MEDIUM**, and **LOW** severity.

---

## 2. Target Files & Isolation Boundaries
- Scope: `src/mcp_vulnerabilities/site_builder.py`, `src/mcp_vulnerabilities/cache.py`, `src/mcp_vulnerabilities/catalog.py`
- Test Suite: `tests/audit/test_audit_task65.py`
- Audit Deliverable: `docs/audit/audit_task65_site_builder_cache.md`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Bit-for-Bit Deterministic Parallel Build Invariant
- **Preconditions**: Build the complete security catalog dataset using `--workers 1` into directory `A`, and `--workers 4` (or 8) into directory `B` from identical input data.
- **Invariants**:
  - [x] **INVARIANT_1A (Bit-for-Bit Byte Equality)**: All generated JSON artifacts (`servers.json`, `index.json`, `updates.json`, and sharded server details) must have identical cryptographic SHA-256 hashes regardless of worker count.
  - [x] **INVARIANT_1B (Deterministic Key Sorting)**: All JSON serialization must use `sort_keys=True` and monotonic sorting by server identifier to prevent order jitter.

### Scenario 2: Worker Process Failure & Isolation Resilience Invariant
- **Preconditions**: Inject a simulated worker crash (e.g. fatal `ProcessLookupError`, synthetic `SystemExit`, or `SIGTERM`) into a single batch during parallel generation.
- **Invariants**:
  - [x] **INVARIANT_2A (Non-Fatal Batch Isolation)**: A single worker process crash must not deadlock the `ProcessPoolExecutor` or terminate the entire build run.
  - [x] **INVARIANT_2B (Partial Failure Triage & Graceful Degradation)**: Unrecoverable server packages must be skipped and logged in `build_errors.json`, allowing the remaining 5,000+ valid servers to be compiled successfully.

### Scenario 3: Cache Invalidation & Stale Entry Eviction Invariant
- **Preconditions**: Build dataset with caching enabled. Mutate one vulnerability record in `data/vulnerabilities` and rebuild.
- **Invariants**:
  - [x] **INVARIANT_3A (Content-Addressed Invalidation)**: The cache key must incorporate the hash of the vulnerability dataset stamp; mutating any vulnerability record must invalidate the affected server cache entries immediately.
  - [x] **INVARIANT_3B (Zero Stale Data Ingress)**: The resulting output after a mutation must reflect the new vulnerability count, verifying zero stale cache reads.

---

## 4. Implementation Steps

1. Author live empirical test suite `tests/audit/test_audit_task65.py` verifying all 3 scenarios and invariants.
2. Run live verification across `site_builder.py` and `cache.py`; fix any edge-case failures.
3. Author comprehensive technical report in `docs/audit/audit_task65_site_builder_cache.md` detailing all evaluated invariants, findings graded by HIGH/MEDIUM/LOW, and concrete patch proposals.

## Non-Interactive Completion Directive
Execute this task end-to-end without asking interactive questions. Implement `tests/audit/test_audit_task65.py`, verify that all tests pass (`pytest -q`), generate the complete technical report in `docs/audit/audit_task65_site_builder_cache.md`, and conclude directly with a complete patch so the remote environment cleanly transitions to `Completed`.

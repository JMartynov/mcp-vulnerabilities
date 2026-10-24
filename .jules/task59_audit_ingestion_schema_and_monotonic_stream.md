# Task 59: Empirical Audit — Ingestion, OSV 1.6 Schema Normalization & Monotonic Stream (P0)

## 1. Architectural Context & Technical Objective

The vulnerability ingestion engine (`pipeline.py`, `deduplicator.py`, `converters/*.py`, `validator.py`, `state.py`) forms the foundational bedrock of `mcp-vulnerabilities`. If OSV range conversions, commit delta cursors, or deduplication algorithms produce flawed or non-monotonic data, all downstream scanners, web catalog shards, and client auto-fixers inherit false positives or critical false negatives.

This task conducts an autonomous, live empirical audit of the ingestion subsystem across all invariants, stress tests error boundaries against corrupt inputs and network dropouts, produces an automated verification suite in `tests/audit/test_audit_task59.py`, and publishes a comprehensive technical report to `docs/audit/audit_task59_ingestion_and_schema.md` categorizing all findings by **HIGH**, **MEDIUM**, and **LOW** severity.

---

## 2. Target Files & Isolation Boundaries
- Scope: `src/mcp_vulnerabilities/pipeline.py`, `src/mcp_vulnerabilities/deduplicator.py`, `src/mcp_vulnerabilities/validator.py`, `src/mcp_vulnerabilities/state.py`, `src/mcp_vulnerabilities/converters/*.py`
- Test Suite: `tests/audit/test_audit_task59.py`
- Audit Deliverable: `docs/audit/audit_task59_ingestion_and_schema.md`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: OSV 1.6 Range Integrity & Deduplication Invariant
- **Preconditions**: Ingest multi-source vulnerability payloads (GHSA, NVD CVE JSON 5.0, OSV.dev) with intersecting and conflicting version ranges.
- **Invariants**:
  - [x] **INVARIANT_1A (Range Monotonicity)**: Every range pair `(introduced, fixed)` must satisfy `introduced < fixed` under SemVer sorting. Unfixed vulnerabilities must explicitly stamp `fixed: null` or preserve open ranges without schema corruption.
  - [x] **INVARIANT_1B (Non-Destructive Deduplication)**: When merging duplicate advisory IDs across GitHub and NVD, unique affected packages, CVSS vectors, and CWE IDs must be preserved additively without dropping events.

### Scenario 2: Monotonic Stream Sync & Mid-Batch Recovery Invariant
- **Preconditions**: Simulate an abrupt process interruption / SIGINT halfway through a 1,000-advisory ingestion stream.
- **Invariants**:
  - [x] **INVARIANT_2A (State Atomicity)**: `sync_state.json` must only commit checkpoints for completely ingested batches. Partial batches must roll back or resume idempotently from the last valid marker.
  - [x] **INVARIANT_2B (Idempotent Monotonicity)**: Re-running ingestion from a checkpoint must yield the exact same advisory count and dataset SHA-256 hash without duplicate records.

### Scenario 3: Corrupt Schema Resilience Invariant
- **Preconditions**: Ingest malformed payloads (invalid SemVer like `1.0.0-rc.1.0.beta`, missing package names, circular Git commit commit ranges, negative CVSS scores).
- **Invariants**:
  - [x] **INVARIANT_3A (Graceful Schema Gating)**: The validator must reject malformed records with explicit validation warnings without crashing the batch worker.
  - [x] **INVARIANT_3B (Valid Record Isolation)**: All valid records within the same stream must be ingested and indexed without hindrance.

---

## 4. Implementation Steps

1. Author live empirical test suite `tests/audit/test_audit_task59.py` verifying all 3 scenarios and invariants.
2. Run live verification across the ingestion codebase and identify any bugs, edge-case crashes, or range anomalies.
3. Apply any lightweight code fixes to ensure 100% test passing.
4. Author comprehensive technical report in `docs/audit/audit_task59_ingestion_and_schema.md` detailing all evaluated invariants, findings graded by HIGH/MEDIUM/LOW, and concrete patch proposals.

## Non-Interactive Completion Directive
Execute this task end-to-end without asking interactive questions. Implement `tests/audit/test_audit_task59.py`, verify that all tests pass (`pytest -q`), generate the complete technical report in `docs/audit/audit_task59_ingestion_and_schema.md`, and conclude directly with a complete patch so the remote environment cleanly transitions to `Completed`.

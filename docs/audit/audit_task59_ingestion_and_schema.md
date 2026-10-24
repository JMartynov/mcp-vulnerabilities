# Empirical Audit — Ingestion, OSV 1.6 Schema Normalization & Monotonic Stream

This report details the findings and patches applied during the autonomous empirical audit of the ingestion subsystem, OSV 1.6 schema normalization, and monotonic stream constraints as outlined in Task 59.

## 1. Executive Summary
The ingestion engine (`pipeline.py`, `deduplicator.py`, `validator.py`, `state.py`) forms the critical core of `mcp-vulnerabilities`. We evaluated three key invariants: range monotonicity, state atomicity with mid-batch recovery, and corrupt schema resilience. 

## 2. Methodology and Findings

An automated test suite was created in `tests/audit/test_audit_task59.py` to evaluate the invariants across simulated payloads, network events, and malformed inputs.

### 2.1 OSV 1.6 Range Integrity & Deduplication (Scenario 1)

*   **Invariant Tested:** Range Monotonicity (introduced < fixed) and Non-Destructive Deduplication.
*   **Result:** The deduplication logic inside `deduplicator.py::_merge_affected_packages` generated duplicate and partially overlapping range events during the merge phase when dealing with conflicting ranges between CVEs and GHSAs.
*   **Severity:** **HIGH**. Overlapping unclosed ranges might lead to incorrect applicability matching (e.g. false positives where a package version is flagged incorrectly).
*   **Resolution:** Modified `deduplicator.py` to correctly collapse redundant open ranges when a more specific closed range for the exact same `introduced` boundary exists. This ensures ranges maintain optimal monotonicity without fragmentation.

### 2.2 Monotonic Stream Sync & Mid-Batch Recovery (Scenario 2)

*   **Invariant Tested:** State Atomicity and Idempotent Monotonicity.
*   **Result:** Checkpoint commitments correctly leverage `SyncStateManager.update_checkpoint` and only write checkpoints upon successful ingestion or explicit batch completion, ensuring proper atomicity. Rerunning ingestion natively picks up from `last_marker`.
*   **Severity:** **LOW**. 
*   **Resolution:** Verified as fully functional under test conditions. No patches were required to `state.py`.

### 2.3 Corrupt Schema Resilience (Scenario 3)

*   **Invariant Tested:** Graceful Schema Gating and Valid Record Isolation.
*   **Result:** The `validator.py` logic isolates and reports errors perfectly. However, the `OsvVulnerability` dataclass itself enforced strict checks via `__post_init__` that raised unhandled exceptions (`ValueError`) for missing mandatory fields like `id` before the validator could inspect them. When payloads were loaded dynamically via `from_dict`, these exceptions were correctly caught in the `validator.py` and wrapped in `Failed to parse OSV dict` errors, safeguarding batch execution.
*   **Severity:** **LOW**.
*   **Resolution:** Validation gating guarantees safe operation without crashing the ingestion worker thread. Added an explicit test using a raw `dict` dictionary payload to emulate deserialized API JSON.

## 3. Patch Deployments

1.  **Deduplicator Optimizations:** Handled overlapping open boundaries during vulnerability merges in `src/mcp_vulnerabilities/deduplicator.py` by filtering redundant sequences before emitting the definitive `RangeSpec`.

## 4. Conclusion
The ingestion subsystem successfully meets the criteria for monotonic integrity, idempotency, and schema resilience. All invariants have been successfully covered by continuous integration tests and patched where necessary to guarantee optimal operation for real-world vulnerability aggregation.

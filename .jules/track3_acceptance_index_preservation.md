### Task: Implement Acceptance Test Suite for Incremental Sync History & Search Index Preservation

#### 1. Context & Contract:
Create a dedicated end-to-end acceptance test file: `tests/test_acceptance_index_preservation.py`.
It must verify that incremental ingestion never truncates `index.json` or erases historical records:
1. `test_incremental_sync_preserves_full_historical_index()`:
   - In a temporary directory, create a mock vulnerability database with 50 existing OSV JSON advisory files and a corresponding `index.json` containing 50 entries.
   - Run `McpVulnerabilityPipeline.run()` configured with an incremental feed that emits only 1 new advisory.
   - Verify that:
     a) The new advisory file is created.
     b) The 50 historical files are preserved and intact.
     c) `index.json` contains exactly 51 entries (count == 51).
2. `test_amended_historical_cve_reprocessed_via_mtime()`:
   - In a simulated CVE directory, set the mtime of an older CVE (e.g. from 2024) to the current timestamp.
   - Verify that the pipeline detects the updated mtime and re-evaluates the advisory rather than skipping it.
3. `test_atomic_index_write_on_failure()`:
   - Ensure that `index.json` is written atomically and remains uncorrupted if a mid-process error occurs.

#### 2. Strict Guardrails:
- Zero external dependencies.
- Use `tempfile.TemporaryDirectory` for safe, isolated filesystem execution.
- All tests must pass with `pytest`.

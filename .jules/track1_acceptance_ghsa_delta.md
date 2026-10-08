### Task: Implement Acceptance Test Suite for Live GHSA Pagination & CVEListV5 Delta Traversal

#### 1. Context & Contract:
Create a dedicated end-to-end acceptance test file: `tests/test_acceptance_ghsa_delta.py`.
It must verify that the new GHSA API pagination and CVEListV5 delta crawler operate correctly across multi-page feeds and multiple commits:
1. `test_ghsa_pagination_follows_link_headers()`:
   - Mock or query GHSA responses where the HTTP `Link` header provides `rel="next"`.
   - Verify that the pipeline follows the pagination links and ingests advisories from subsequent pages into `collected`.
2. `test_ghsa_since_cursor_checkpointing()`:
   - Execute a simulated sync run. Verify that `state_manager.get_checkpoint("ghsa_api").last_updated_at` records the newest advisory's timestamp.
   - Run a subsequent sync and assert that the request URL includes `&since=<timestamp>`.
3. `test_cvelist_delta_multi_commit_traversal()`:
   - Simulate a repository commit history where 3 commits were pushed since the previous run.
   - Verify that the delta crawler inspects all 3 commits until reaching `last_marker`, updating `last_marker` to the newest commit SHA.

#### 2. Strict Guardrails:
- Must use standard unittest or pytest conventions.
- Tests must be deterministic and robust. Use unittest.mock where remote network calls could be flaky or rate-limited.
- All tests must pass with `pytest`.

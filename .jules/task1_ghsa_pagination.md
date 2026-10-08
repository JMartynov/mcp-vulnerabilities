### Task: Implement GHSA Live API Pagination & CVEListV5 Multi-Commit Traversal

#### 1. Context & Contract:
In `src/mcp_vulnerabilities/pipeline.py` and `src/mcp_vulnerabilities/state.py`:
1. In GHSA API ingestion (`pipeline.py:238-280`):
   - Replace single-page query with `since` cursor and pagination support.
   - Use `last_updated_at` from `self.state_manager.get_checkpoint("ghsa_api")`. If present, append `&since={last_updated_at}` to the GitHub API query URL.
   - Support pagination by checking the HTTP `Link` header for `rel="next"` or iterating pages up to `max_pages=5` (up to 500 advisories per run) so occurrences beyond page 1 are not dropped.
   - Update `state_manager.update_checkpoint("ghsa_api", last_updated_at=newest_advisory_updated_at, records_scanned=..., records_synced=...)`.
2. In CVEListV5 delta ingestion (`pipeline.py:281-337`):
   - Store last processed commit SHA in `self.state_manager.get_checkpoint("cvelist_delta").last_marker`.
   - Instead of looking only at `commits[0]`, iterate through commits until `last_marker` is encountered, so multiple commits pushed between daily runs are inspected.
   - Update `state_manager.update_checkpoint("cvelist_delta", last_marker=head_sha, ...)`.

#### 2. Strict Guardrails:
- Zero unauthorized external dependencies. Use standard library `urllib`, `json`, `datetime`.
- Preserve existing function signatures.
- Do not break offline / test fixture ingestion.

#### 3. Testing:
- Add tests in `tests/test_osv_sync_state.py` or `tests/test_osv_pipeline.py` verifying pagination and checkpoint resumption.
- All tests must pass with `pytest`.

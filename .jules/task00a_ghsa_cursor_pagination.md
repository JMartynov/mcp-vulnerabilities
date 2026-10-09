### Task: GHSA Stream Cursor Pagination & Commit Delta Traversal (Foundational 00-A)

#### 1. Architectural Context & Purpose:
The GitHub Security Advisory (GHSA) API streams live vulnerability advisories affecting the MCP ecosystem. Previously, the ingestion pipeline only fetched the first page (`per_page=100`), discarding advisories beyond the 100th record. Furthermore, incremental synchronization did not preserve the RFC 5988 `Link` pagination cursor or track commit delta traversals, resulting in missing historical advisories and incomplete vulnerability datasets.
Hardening this stream ensures complete, paginated historical backfills and efficient incremental syncing via commit SHAs and `since` timestamp cursors.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/pipeline.py`: Methods `_sync_ghsa_api()`, `_sync_cvelist_delta()`, and `_get_github_headers()`.
* `src/mcp_vulnerabilities/sync_state.py`: Class `SyncStateManager` tracking `last_updated_at` and `last_marker`.
* `tests/test_acceptance_ghsa_delta.py`: Acceptance test suite verifying pagination and delta traversal.

#### 3. Engineering & Implementation Blueprint:
1. **RFC 5988 Link Header Pagination**:
   - Parse HTTP `Link` response headers looking for `rel="next"` URLs.
   - Loop sequentially until no further pages exist, aggregating all pages into the sync buffer.
   - Respect GitHub rate-limiting headers (`X-RateLimit-Remaining`, `X-RateLimit-Reset`) with exponential backoff on HTTP 403/429.
2. **Incremental Commit Delta Traversal**:
   - In `_sync_cvelist_delta()`, store the latest processed commit SHA in `sync_state.json`.
   - On subsequent runs, traverse commits backward only until the stored SHA is reached, preventing redundant API calls.
3. **Acceptance Test Suite**:
   - Implement `tests/test_acceptance_ghsa_delta.py` with multi-page mock API responses asserting that 100% of paginated records are collected and state markers are persisted.

#### 4. Guardrails & Security Invariants:
* **Zero Missing Records**: Pagination must exhaust all available pages; truncation is considered a critical sync failure.
* **Rate-Limit Resilience**: Unauthenticated runs must degrade gracefully and warn, while authenticated runs use `GITHUB_TOKEN` to leverage 5,000 req/hr limits.

#### 5. Acceptance Criteria:
- [x] Multi-page GHSA API responses are fully consumed using RFC 5988 `Link` header traversal.
- [x] Ingestion checkpoint records `last_updated_at` and commit SHA markers in `sync_state.json`.
- [x] Exponential backoff is triggered when HTTP 429 or secondary rate limits are encountered.
- [x] Mock acceptance tests in `tests/test_acceptance_ghsa_delta.py` pass with 100% assertions satisfied.

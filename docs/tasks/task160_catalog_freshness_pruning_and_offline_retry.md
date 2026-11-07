# Task 160: Catalog Freshness, Dead Repository Pruning, and Offline Retry Backoff

## Status: IN PROGRESS
**Priority:** P1  
**Components:** Ingestion Pipeline, GitHub Discovery, Offline Health Check  
**Target Files:**
- `src/mcp_vulnerabilities/discovery/pipeline.py`
- `src/mcp_vulnerabilities/discovery/github_curated.py`
- `src/mcp_vulnerabilities/discovery/npm.py`
- `tests/test_catalog_pruning_and_backoff.py`

---

## 1. Objectives & Scope

1. **Deleted & Archived Upstream Pruning:**
   - Detect GitHub HTTP 404 (deleted/pruned repositories) and `archived: true` status during catalog synchronization.
   - Tag pruned repositories in `mcp_catalog_state.json` and suppress them from active recommendations.
2. **Exponential Backoff for Offline Endpoints:**
   - Address the 52.9% offline/unreachable rate (3,179 servers identified in `passport_standard_verification_report.md`).
   - Store consecutive failure counts and a `next_retry_after` timestamp in `sync_state.json` to prevent repetitive timeouts on dead hosts during daily CI syncs.
3. **Verification Suite:**
   - Author `tests/test_catalog_pruning_and_backoff.py` testing archived repo flagging, 404 pruning, and backoff interval calculations.

---

## 2. Acceptance Criteria

- [ ] Archived or deleted upstream repositories are cleanly recognized and filtered.
- [ ] Unreachable servers are backed off exponentially without blocking daily sync runs.
- [ ] `tests/test_catalog_pruning_and_backoff.py` passes 100%.

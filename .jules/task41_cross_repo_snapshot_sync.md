# Task 41: Cross-Repo Snapshot Sync, Daily Workflow Alignment & Final E2E Verification (P0)

## 1. Architectural Context & Technical Objective
Establish automated cross-repository snapshot synchronization and daily workflow alignment between `mcp-fingerprints` and `mcp-vulnerabilities`. Configure `.github/workflows/daily_sync.yml` to ingest the latest structural `passports.json.gz` from `mcp-fingerprints` releases, run the correlation engine, update advisory indexes, rebuild the static web portal, and conduct full end-to-end integration testing across both codebases. Implement robust rate-limiting fallbacks and error handling.

## 2. Target Files & Documentation to Update
- `.github/workflows/daily_sync.yml`
- `.github/workflows/cross_repo_sync.yml`
- `src/mcp_vulnerabilities/sync_manager.py`
- `tests/test_e2e_cross_repo_sync.py`
- `docs/cross_repo_architecture.md`

## 3. EULIS Implementation & Branch Review Workflow
- Branch: `jules/review-task41`
- Implementation PR: `jules-gate pr --skip-ci`
- Offload Mode 2 EULIS Code Review: `jules-gate review-branch`
- Review verification: check `docs/reviews/review_task41.md`
- Test verification: run test suite via isolated subagent (`jules-gate verify`)
- Merge: `jules-gate pr-merge --skip-ci`

## 4. Acceptance & Verification Criteria
- [ ] Daily sync workflow downloads latest release asset from `mcp-fingerprints` via GitHub API.
- [ ] Automated fallback to local snapshot if remote download fails or is rate-limited.
- [ ] Correlation and site building trigger automatically upon new snapshot arrival.
- [ ] Full end-to-end integration test verifies data ingestion, correlation, and site compilation.
- [ ] Cross-repo architecture documentation clearly defines synchronization contracts.

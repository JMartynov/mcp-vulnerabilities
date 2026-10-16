# Task 39: Version-Aware Unified Site Builder & Sharded Server Datasets (P0)

## 1. Architectural Context & Technical Objective
Refactor `src/mcp_vulnerabilities/site_builder.py` into a high-performance static site generator that produces version-aware security datasets. Shard the massive 5,000+ server database into lightweight, partitioned JSON datasets (e.g. `docs/data/servers/`, `docs/data/advisories/`, `docs/data/index.json`) to enable sub-100ms static page loads in web browsers without huge monolithic JSON payloads. Embed version matrices, capability risk ratings, and CWE/OWASP tags directly into the sharded site payloads.

## 2. Target Files & Documentation to Update
- `src/mcp_vulnerabilities/site_builder.py`
- `src/mcp_vulnerabilities/sharder.py`
- `tests/test_site_builder.py`
- `tests/test_sharder.py`
- `docs/site_builder_architecture.md`

## 3. EULIS Implementation & Branch Review Workflow
- Branch: `jules/review-task39`
- Implementation PR: `jules-gate pr --skip-ci`
- Offload Mode 2 EULIS Code Review: `jules-gate review-branch`
- Review verification: check `docs/reviews/review_task39.md`
- Test verification: run test suite via isolated subagent (`jules-gate verify`)
- Merge: `jules-gate pr-merge --skip-ci`

## 4. Acceptance & Verification Criteria
- [ ] `site_builder.py` outputs sharded JSON files partitioned by ecosystem and initial package characters.
- [ ] Root search index (`docs/data/index.json`) optimized for sub-100KB initial page load.
- [ ] Server shards include complete version histories, tool capability risks, and associated advisories.
- [ ] Site generator runs incrementally and handles 5,000+ servers in <30 seconds.
- [ ] Tests verify shard structure, valid JSON formatting, and absence of broken links.

# Task 36: Multi-Server Conflict Detector, Automated Resolver, SARIF Collision Rules & Config Exporters Migration (P0)

## 1. Architectural Context & Technical Objective
Migrate, integrate, and extend the multi-server conflict detector (`conflict_detector.py`), automated config resolver (`conflict_resolver.py`), SARIF collision rules (`sarif.py`), and client configuration exporters (Claude Desktop, Cursor, Zed, Cline, Windsurf) into `mcp-vulnerabilities`. Identify tool shadowing, command collisions, and capability overlaps across multi-server configurations. Implement resolution strategies (prefix namespacing, priority routing, tool masking), export native client configurations, and emit OASIS SARIF v2.1.0 collision reports with exact rule definitions.

## 2. Target Files & Documentation to Update
- `src/mcp_vulnerabilities/fingerprints/conflict_detector.py`
- `src/mcp_vulnerabilities/fingerprints/conflict_resolver.py`
- `src/mcp_vulnerabilities/config_exporter.py`
- `src/mcp_vulnerabilities/sarif.py`
- `tests/test_conflict_detector.py`
- `tests/test_conflict_resolver.py`
- `tests/test_config_exporter.py`
- `docs/conflict_resolution_and_exporters.md`

## 3. EULIS Implementation & Branch Review Workflow
- Branch: `jules/review-task36`
- Implementation PR: `jules-gate pr --skip-ci`
- Offload Mode 2 EULIS Code Review: `jules-gate review-branch`
- Review verification: check `docs/reviews/review_task36.md`
- Test verification: run test suite via isolated subagent (`jules-gate verify`)
- Merge: `jules-gate pr-merge --skip-ci`

## 4. Acceptance & Verification Criteria
- [ ] Conflict detector detects exact name collisions and conflicting tool capabilities across multiple servers.
- [ ] Conflict resolver supports `prefix`, `priority`, and `filter` strategies with automated config rewriting.
- [ ] Native config exporters support Claude Desktop, Cursor, Zed, Cline, and Windsurf formats.
- [ ] SARIF exporter includes specialized collision and shadowing rules with line annotations.
- [ ] Comprehensive unit tests in `tests/test_conflict_detector.py`, `tests/test_conflict_resolver.py`, and `tests/test_config_exporter.py`.

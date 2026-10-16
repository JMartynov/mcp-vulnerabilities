# EULIS Branch Code Review: Task 36 (Conflict Detector, Resolver, SARIF & Exporters)

**Branch Under Review**: `jules/review-task36`  
**Base Branch**: `main`  
**Review Target**: `src/mcp_vulnerabilities/audit/conflict_detector.py`, `src/mcp_vulnerabilities/audit/conflict_resolver.py`, `src/mcp_vulnerabilities/audit/config_exporter.py`, `src/mcp_vulnerabilities/audit/parsers.py`, `src/mcp_vulnerabilities/audit/reporters.py`, `tests/test_conflict_*.py`, `tests/test_sarif_collisions.py`, `tests/test_config_exporter.py`, `docs/IMPLEMENTATION.md`  
**Status**: `#Correct#` / Approved with Verified Refinements  

---

## 1. Executive Summary
Task 36 completes the migration and unification of client configuration security tooling into `mcp-vulnerabilities`. It enables automated detection of conflicting tool names, shadowing risks, and signature divergence across multi-server installations (Claude Desktop, Cursor, Cline, Zed, Windsurf), providing remediation via `prefix` and `priority` strategies, native configuration exporters, and OASIS SARIF v2.1.0 collision rule reports.

---

## 2. Verified Architectural Criteria
- **VC-36V.1**:
  - `src/mcp_vulnerabilities/audit/conflict_detector.py` implements `ToolInstance`, `ToolCollision`, `ConflictAuditReport`, `audit_client_config`, `format_audit_report`, `extract_package_from_server_config`, and `load_passport_index` supporting both JSON directories and compressed gzip archives (`data/passports.json.gz`).
  - `src/mcp_vulnerabilities/audit/conflict_resolver.py` implements `ResolveResult` and `resolve_client_config` with `prefix`, `priority`, and `report` strategies.
  - `src/mcp_vulnerabilities/audit/config_exporter.py` implements `ClaudeExporter`, `CursorExporter`, `ClineExporter`, `ZedExporter`, `WindsurfExporter`, `DockerExporter`, and `patch_jsonc`.
  - `SarifReporter.generate_collision_sarif` in `src/mcp_vulnerabilities/audit/reporters.py` emits `MCP-STRUCTURAL-COLLISION-*` rules.
  - `ClientConfigParser.parse_dict` in `src/mcp_vulnerabilities/audit/parsers.py` supports Zed `context_servers`.
  - Backward compatibility shims in `src/mcp_vulnerabilities/fingerprints/conflict_detector.py`, `conflict_resolver.py`, and `src/mcp_vulnerabilities/config_exporter.py`.
  - All unit test suites pass 100%: `tests/test_conflict_detector.py`, `tests/test_conflict_resolver.py`, `tests/test_sarif_collisions.py`, `tests/test_config_exporter.py`.
  - Fixtures `tests/fixtures/configs/colliding_cursor_config.json` and `valid_claude_desktop_config.json` are present.
- **VC-36V.2**: `docs/IMPLEMENTATION.md` Section 5 and `docs/reviews/review_task36.md` are documented and committed.

---

## 3. Code Quality & Security Assessment
- **Schema Resilience**: Robust normalization handles nested Zed command objects (`{"command": {"path": ..., "args": ...}}`) alongside standard `{command, args}` dictionaries.
- **Comment-Safe Patching**: `patch_jsonc()` preserves human comments in client configuration files.
- **Code Scanning Integration**: Structural collisions are assigned appropriate SARIF severity levels (`error` vs `warning`) mapped from risk tiers.

# Task 81: Latest-Version (`versions[-1]`) Analytics & Catalog Tool Ingestion Fix (P1)

**Defect Reference:** `DEFECT-W14-05` ([`docs/reports/code_review_wave14_portal_and_analytics.md`](../reports/code_review_wave14_portal_and_analytics.md))  
**Target Wave:** Wave 15A (Wave 14 Code Review Remediation)  
**Priority:** `P1` (Analytics & Catalog Accuracy Fix)

---

## 1. Architectural Context & Technical Objective

In `src/mcp_vulnerabilities/site_builder.py`, server `version_records` are sorted in **ascending** SemVer order (`version_records.sort(key=lambda r: _parse_sort_version(r.version))` at lines 153 and 378). Consequently:
- `versions[0]` is the **oldest historical version** (e.g., `0.0.1-alpha`),
- `versions[-1]` is the **latest version** (as correctly used at line 191: `latest_v_record = version_records[-1]`).

However, two downstream loops in `build_site_parallel()` mistakenly index `versions[0]`:
1. **Catalog Index Tool Extraction (~line 506)**:
   ```python
   versions = record.get("versions", [])
   tools = versions[0].get("tools", []) if versions else []
   ```
   If a package had 0 tools in `v0.1.0` and added 8 tools in `v1.0.0`, `mcp_catalog_index.json` stamps `tools_count: 0` and `tools_sample: []`.
2. **Analytics Capability & Secrets Perimeter Aggregation (~line 651)**:
   ```python
   versions = pkg_data.get("versions", [])
   if not versions:
       continue
   v = versions[0]
   req_envs = v.get("required_env_vars", [])
   ```
   Because `versions[0]` is inspected instead of `versions[-1]` (and `pkg_data.get("required_env_vars", [])` is not merged), new tools and required environment variables introduced in later releases are completely missed in `docs/data/analytics.json`.

This task fixes both sites in `src/mcp_vulnerabilities/site_builder.py` to select the latest version (`versions[-1]`, with fallback to the newest version that has non-empty `tools` if `versions[-1]` has none) and union `v.get("required_env_vars", [])` with `pkg_data.get("required_env_vars", [])`.

---

## 2. Target Files & Isolation Boundaries

- **Primary File:** `src/mcp_vulnerabilities/site_builder.py`
- **Coordination:** Coordinate with Task 79 (which also edits `src/mcp_vulnerabilities/site_builder.py`). Do NOT rebuild the full production dataset in the Cloud VM; verify using unit test fixtures.

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Latest-Version Tool & Capability Selection (`INVARIANT_81_1A`)
- **Preconditions**: A server passport has multiple versions sorted ascending: `v0.1.0` (1 read-only tool, 0 env vars) and `v1.2.0` (3 tools including `exec_command`, `required_env_vars: ["OPENAI_API_KEY"]`).
- **Invariants**:
  - [ ] **INVARIANT_81_1A (Catalog Index Latest Tools)**: `mcp_catalog_index.json` records `tools_count == 3` and `tools_sample` containing the 3 tools from `v1.2.0` (`versions[-1]`).
  - [ ] **INVARIANT_81_1B (Fallback for Empty Latest Version)**: If `versions[-1]` has `tools == []` (e.g., an unenriched metadata-only bump) but an earlier version in `reversed(versions)` has non-empty `tools`, `_select_representative_version(versions)` selects the newest version with tools for tool/capability extraction.
  - [ ] **INVARIANT_81_1C (Analytics Secrets & Capabilities)**: `analytics.json` counts `OPENAI_API_KEY` in `secrets_perimeter` and increments `shell_execution` in `capability_surface`.
  - [ ] **INVARIANT_81_1D (Bit-for-Bit Determinism)**: Output JSON files remain 100% deterministic across worker counts (`tests/audit/test_audit_task65.py` and `tests/test_parallel_site_builder.py` pass).

---

## 4. Concrete Implementation Instructions

1. In `src/mcp_vulnerabilities/site_builder.py`, add helper `_select_representative_version(versions: list[dict[str, Any]]) -> dict[str, Any]`:
   ```python
   def _select_representative_version(versions: list[dict[str, Any]]) -> dict[str, Any]:
       """Return the latest version (versions[-1]), or the newest version with extracted tools."""
       if not versions:
           return {}
       for v in reversed(versions):
           if isinstance(v, dict) and v.get("tools"):
               return v
       return versions[-1] if isinstance(versions[-1], dict) else {}
   ```
2. At ~line 506 in `build_site_parallel()`, replace:
   ```python
   versions = record.get("versions", [])
   tools = versions[0].get("tools", []) if versions else []
   ```
   with:
   ```python
   versions = record.get("versions", [])
   rep_version = _select_representative_version(versions)
   tools = rep_version.get("tools", [])
   ```
3. At ~line 651 in the analytics loop in `build_site_parallel()`, replace `v = versions[0]` with `v = _select_representative_version(versions)` and collect required environment variables from `v.get("required_env_vars") or pkg_data.get("required_env_vars") or []`.
4. Run `.venv/bin/pytest -q` to ensure zero regressions.

---

## 5. Non-Interactive Completion Directive

Complete all implementation steps, verify all invariants locally with pytest fixtures, and commit directly without asking open-ended questions so the session cleanly transitions to `Completed`.

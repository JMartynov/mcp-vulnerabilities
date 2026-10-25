# Task 89: Passports Pipeline Fix & Static Data Recompilation (P0)

**Subsystem:** Pipeline & Data Engine (`src/mcp_vulnerabilities/site_builder.py`, `docs/data/`)  
**Priority:** `P0`  
**Parent Plan:** [IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md](IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md)

---

## 1. Objective & Problem Statement
Currently on the live web portal:
1. `docs/data/mcp_catalog_index.json` lacks the precomputed `"composite_risk_tier"` and `"highest_cve_severity"` fields because the site data has not been recompiled since Tasks 79 and 81 were merged.
2. `docs/data/analytics.json` renders `"top_secrets": []` ("No secrets data available") and `"transports": {}` ("No data") because:
   - In `site_builder.py#L924`, `--passports` defaults to `None`.
   - In `site_builder.py#L791`, `if passports_path:` skips loading when `None`.
   - `site_builder.py` only extracts from `v.get("required_env_vars")` (which is empty in passports) while ignoring `versions[*].connections[*].configSchema.properties` (where 1,377 connections declare keys like `x-api-key`, `api_key`, `client_id`, `client_secret`, `wallet_private_key`).
   - Transport extraction from `data/passports.json.gz` failed because it checked `isinstance(passports_data, dict)` while `data["passports"]` is a list of server objects in some schemas or dict in others, and missed `connections[*].type` (`streamable-http`, `http`, `sse`, `stdio`).

---

## 2. Detailed Technical Requirements

### 2.1 Passports Pipeline & Extraction Fixes (`src/mcp_vulnerabilities/site_builder.py`)
1. In `site_builder.py`, update `--passports` CLI default and function defaults to check if `"data/passports.json.gz"` exists on disk, using it automatically if `passports_path is None`.
2. Ensure transport aggregation counts both top-level `passport.get("transport")` AND version connections `c.get("type")` (`streamable-http`, `sse`, `stdio`, `http`).
3. For Secrets Perimeter aggregation, extract credential keys from:
   - `v.get("required_env_vars", [])`
   - `v.get("headers_schema", {}).get("properties", {}).keys()`
   - `v.get("connections", [])` -> `c.get("configSchema", {}).get("properties", {}).keys()`
   - Populate `top_secrets` in `analytics.json` with the most frequent configuration and secret property names.
4. Ensure `shards/` records retain `connections` array so the frontend modal can display deployment URLs and configuration schemas.

### 2.2 Static Data Recompilation
1. Run `python -m mcp_vulnerabilities.site_builder --passports data/passports.json.gz --no-cache`.
2. Verify that `docs/data/mcp_catalog_index.json` has `composite_risk_tier` and `highest_cve_severity` on every entry.
3. Verify that `docs/data/analytics.json` has populated `transports` (with `stdio`, `streamable-http`, `http`, `sse`) and populated `top_secrets`.

---

## 3. Acceptance Criteria
- [ ] `site_builder.py` defaults to `data/passports.json.gz` if present.
- [ ] `docs/data/mcp_catalog_index.json` contains `composite_risk_tier` on all 6,289 records.
- [ ] `docs/data/analytics.json` contains non-empty `transports` and `top_secrets`.
- [ ] Unit tests in `tests/test_analytics.py` and `tests/test_site_builder_unified.py` pass 100%.
- [ ] Deterministic JSON formatting (`sort_keys=True`) preserved across all compiled files.

---

## 4. Operational Directives
- **Non-Interactive Completion Directive:** Complete implementation and verification autonomously without waiting for human input.
- **Dataset Guard:** Rebuild site data locally and verify with targeted pytest assertions.

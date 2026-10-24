# Task 79: Precomputed `composite_risk_tier` & `highest_cve_severity` in Catalog Index (P0)

**Defect Reference:** `DEFECT-W14-02` ([`docs/reports/code_review_wave14_portal_and_analytics.md`](../reports/code_review_wave14_portal_and_analytics.md))  
**Target Wave:** Wave 15A (Wave 14 Code Review Remediation)  
**Priority:** `P0` (Critical Data Starvation & Risk Scoring Fix)

---

## 1. Architectural Context & Technical Objective

In `docs/app.js` (~lines 683–710) and `docs/updates.js`, `getServerCompositeRisk(server)` attempts to compute a server's effective security risk tier by iterating over `server.versions` and inspecting `v.advisories`. However, in `src/mcp_vulnerabilities/site_builder.py` (~lines 505–545), `mcp_catalog_index.json` is built **without** the `versions` array so the initial index payload remains compact.

Because `server.versions` is `undefined` on every catalog index item, `getServerCompositeRisk(server)` silently skips the loop and falls back to `server.static_risk_tier` (which defaults to `"LOW"` for servers without extracted static tool schemas). As a result, all 344+ vulnerable servers — including servers afflicted with CVSS 9.8 Critical Remote Code Execution CVEs (e.g. `CVE-2025-10193`) — falsely render `Risk: LOW` on directory cards, defeating `INVARIANT_3A` of Task 73.

This task resolves the data starvation at the source by precomputing and stamping `highest_cve_severity` and `composite_risk_tier` into each `catalog_index` entry inside `src/mcp_vulnerabilities/site_builder.py`, and updating `getServerCompositeRisk(server)` in `docs/app.js` and `docs/updates.js` to consume `server.composite_risk_tier`.

---

## 2. Target Files & Isolation Boundaries

- **Primary Files:**
  - `src/mcp_vulnerabilities/site_builder.py`
  - `docs/app.js`
  - `docs/updates.js`
- **Coordination:** Coordinate with Task 81 (which also modifies `src/mcp_vulnerabilities/site_builder.py`). Do NOT run full 5,820-server dataset regeneration inside the Cloud VM; verify using unit test fixtures.

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Deterministic Severity Extraction & Composite Risk Stamping (`INVARIANT_79_1A`)
- **Preconditions**: `build_site_parallel()` processes a server with `static_risk_tier = "LOW"` and at least one vulnerable version containing an advisory with `severity = "CRITICAL"` (either in `adv["database_specific"]["severity"]`, `adv["affected"][0]["database_specific"]["severity"]`, or `adv["severity"]`).
- **Invariants**:
  - [ ] **INVARIANT_79_1A (Index Fields Present)**: Every item in `mcp_catalog_index.json` includes `"highest_cve_severity"` (`"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | None`) and `"composite_risk_tier"` (`"CRITICAL" | "HIGH" | "MEDIUM" | "LOW"`).
  - [ ] **INVARIANT_79_1B (Severity Promotion)**: For any server with `is_vulnerable=True`, `composite_risk_tier` equals `max(static_risk_tier, highest_cve_severity)` ordered by `CRITICAL (4) > HIGH (3) > MEDIUM/MODERATE (2) > LOW (1)`. `"MODERATE"` is normalized to `"MEDIUM"`. If `is_vulnerable=True` but no explicit severity string is present on the advisory, `highest_cve_severity` defaults to `"HIGH"`.
  - [ ] **INVARIANT_79_1C (Non-Vulnerable Preservation)**: For any server with `is_vulnerable=False`, `highest_cve_severity` is `None` and `composite_risk_tier` equals `(static_risk_tier or "LOW").upper()`.
  - [ ] **INVARIANT_79_1D (Bit-for-Bit Determinism)**: `mcp_catalog_index.json` remains 100% deterministic (`sort_keys=True`) across 1 and 4 workers (`tests/audit/test_audit_task65.py` and `tests/test_parallel_site_builder.py` pass).

### Scenario 2: Frontend Consumption in `docs/app.js` and `docs/updates.js` (`INVARIANT_79_2A`)
- **Preconditions**: `renderDirectoryCards()` in `docs/app.js` or `renderUpdatedServers()` in `docs/updates.js` renders a server entry from `mcp_catalog_index.json` (where `versions` is omitted).
- **Invariants**:
  - [ ] **INVARIANT_79_2A (Precomputed Field Priority)**: `getServerCompositeRisk(server)` checks `if (server.composite_risk_tier) return server.composite_risk_tier.toUpperCase();` (or compares `server.highest_cve_severity` against `server.static_risk_tier`) before falling back to `server.versions` iteration.
  - [ ] **INVARIANT_79_2B (Risk Filter Chip Consistency)**: In `applyDirectoryFilters()` (`docs/app.js` ~line 650), the risk tier filter compares `activeRisk` against `getServerCompositeRisk(server)` (or matches either `getServerCompositeRisk(server)` or `server.static_risk_tier`) so filtering by `CRITICAL` or `HIGH` surfaces cards displaying `Risk: CRITICAL` / `Risk: HIGH`.

---

## 4. Concrete Implementation Instructions

1. In `src/mcp_vulnerabilities/site_builder.py`, add a helper function `_compute_composite_risk(static_risk_tier: str | None, is_vulnerable: bool, versions: list[dict[str, Any]]) -> tuple[str | None, str]`:
   ```python
   _SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "MODERATE": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}
   _RANK_TO_TIER = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "LOW"}

   def _extract_advisory_severity(adv: Any) -> str:
       if not isinstance(adv, dict):
           return "UNKNOWN"
       db_spec = adv.get("database_specific")
       if isinstance(db_spec, dict) and db_spec.get("severity"):
           return str(db_spec["severity"]).upper()
       for aff in adv.get("affected", []) or []:
           if isinstance(aff, dict):
               aff_db = aff.get("database_specific")
               if isinstance(aff_db, dict) and aff_db.get("severity"):
                   return str(aff_db["severity"]).upper()
       sev = adv.get("severity")
       if isinstance(sev, str) and sev:
           return sev.upper()
       return "UNKNOWN"

   def _compute_composite_risk(
       static_risk_tier: str | None,
       is_vulnerable: bool,
       versions: list[dict[str, Any]],
   ) -> tuple[str | None, str]:
       base_tier = (static_risk_tier or "LOW").upper()
       if base_tier == "MODERATE":
           base_tier = "MEDIUM"
       base_rank = _SEVERITY_RANK.get(base_tier, 1)
       if not is_vulnerable:
           return None, _RANK_TO_TIER.get(base_rank, "LOW")

       highest_cve_rank = 0
       for v in versions or []:
           if not isinstance(v, dict) or not v.get("is_vulnerable"):
               continue
           for adv in v.get("advisories", []) or []:
               sev = _extract_advisory_severity(adv)
               rank = _SEVERITY_RANK.get(sev, 0)
               if rank > highest_cve_rank:
                   highest_cve_rank = rank
       if highest_cve_rank == 0:
           highest_cve_rank = 3  # Default vulnerable server without explicit severity to HIGH
       highest_cve_severity = _RANK_TO_TIER[highest_cve_rank]
       composite_rank = max(base_rank, highest_cve_rank)
       return highest_cve_severity, _RANK_TO_TIER[composite_rank]
   ```
2. In `build_site_parallel()` (`src/mcp_vulnerabilities/site_builder.py` ~line 510), call `highest_cve_sev, composite_tier = _compute_composite_risk(record.get("static_risk_tier"), is_vuln, versions)` and include `"highest_cve_severity": highest_cve_sev` and `"composite_risk_tier": composite_tier` in `catalog_index.append({...})`.
3. In `docs/app.js` and `docs/updates.js`, update `getServerCompositeRisk(server)` so that if `server.composite_risk_tier` is defined, it returns `server.composite_risk_tier.toUpperCase()` immediately (while retaining the `server.versions` loop as a fallback when given an unindexed shard object).
4. Validate with `node -c docs/app.js && node -c docs/updates.js` and `.venv/bin/pytest -q`.

---

## 5. Non-Interactive Completion Directive

Complete all implementation steps, verify all invariants locally using test fixtures (do not rebuild the full production dataset in the Cloud VM), and commit directly without asking open-ended questions so the session cleanly transitions to `Completed`.

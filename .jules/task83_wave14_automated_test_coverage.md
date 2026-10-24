# Task 83: Comprehensive Automated Test Suite for Analytics Engine & Wave 14/15 Web Portal (P0)

**Defect Reference:** `DEFECT-W14-04` ([`docs/reports/code_review_wave14_portal_and_analytics.md`](../reports/code_review_wave14_portal_and_analytics.md))  
**Target Wave:** Wave 15B (Wave 14 & 15 Verification Gate)  
**Priority:** `P0` (Mandatory Regression & Contract Test Suite)

---

## 1. Architectural Context & Technical Objective

Task 75 explicitly contracted `tests/test_analytics.py`, which was omitted during Wave 14 delivery. Additionally, none of the Wave 14/15 frontend contracts (`docs/index.html`, `docs/updates.html`, `docs/analytics.html`, `docs/app.js`, `docs/updates.js`, `docs/style.css`) or new `site_builder.py` fields (`composite_risk_tier`, `highest_cve_severity`, `zero_day_gap`, `capability_surface`, `secrets_perimeter`, `transport_topology`, `tool_shadowing`, `versions[-1]` selection) were covered by automated unit/integration tests.

This task authors two dedicated, fast, zero-Playwright test modules (`tests/test_analytics.py` and `tests/test_wave14_portal.py`) that run cleanly in both Python 3.12 and Python 3.14 CI environments without external network calls.

---

## 2. Target Files & Isolation Boundaries

- **New Test Files:**
  - `tests/test_analytics.py`
  - `tests/test_wave14_portal.py`
- **Dependencies:** Runs after Tasks 78–82 are integrated.

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Multi-Dimensional Analytics & Composite Risk Pipeline Tests (`tests/test_analytics.py`)
- **Preconditions**: Construct a synthetic multi-server, multi-version passport and advisory dataset in `tmp_path` and run `build_site_parallel(..., workers=1, use_cache=False)`.
- **Invariants**:
  - [ ] **INVARIANT_83_1A (Zero-Day vs Remediable Patch Gap)**: Verify `analytics["zero_day_gap"]["patched_remediable_count"]` and `analytics["zero_day_gap"]["zero_day_unpatched_count"]` accurately partition vulnerable servers with vs. without a `recommended_safe_version`.
  - [ ] **INVARIANT_83_1B (Latest-Version Capability & Secrets Ingestion — Task 81)**: Given a server with `v0.1.0` (0 tools, no env vars) and `v1.0.0` (tools `read_file`, `exec_shell`, `fetch_url`, `delete_item` and `required_env_vars: ["SECRET_TOKEN"]`), verify `mcp_catalog_index.json` reports `tools_count == 4` and `analytics.json` records `filesystem_access >= 1`, `shell_execution >= 1`, `network_egress >= 1`, `mutating_tools >= 1`, and `secrets_perimeter` includes `"SECRET_TOKEN"`.
  - [ ] **INVARIANT_83_1C (Precomputed Composite Risk Tier — Task 79)**: Verify `mcp_catalog_index.json` stamps `highest_cve_severity: "CRITICAL"` and `composite_risk_tier: "CRITICAL"` on a server with `static_risk_tier: "LOW"` afflicted by a `CRITICAL` advisory, and stamps `highest_cve_severity: None`, `composite_risk_tier: "LOW"` on a clean `LOW` server.
  - [ ] **INVARIANT_83_1D (Tool Shadowing & Transport Topology)**: Verify `tool_shadowing` detects identical tool names with divergent `canonical_hash` values across servers, and `transport_topology` tallies `stdio` vs `sse`.

### Scenario 2: Web Portal DOM, CSS & JS Static Invariant Suite (`tests/test_wave14_portal.py`)
- **Preconditions**: Inspect `docs/index.html`, `docs/updates.html`, `docs/analytics.html`, `docs/app.js`, `docs/updates.js`, and `docs/style.css`.
- **Invariants**:
  - [ ] **INVARIANT_83_2A (JS Syntax Gate)**: Run `node -c docs/app.js` and `node -c docs/updates.js` via `subprocess.run` (skipping gracefully via `pytest.skip` only if `shutil.which("node")` is `None`).
  - [ ] **INVARIANT_83_2B (Task 78 Regression Guard)**: Parse `applyAdvisoryFilters` body in `docs/app.js` and assert it contains no `server.` reference and calls `advisoryHasVulnerableTools`.
  - [ ] **INVARIANT_83_2C (Task 80 CVE/CVSS Auditor Guard)**: Assert `docs/app.js` defines `findMatchingAdvisoriesForPackage` and renders `.audit-cve-list` in `renderAuditResults`.
  - [ ] **INVARIANT_83_2D (Task 82 CSS & HTML Hygiene Guard)**:
    - Assert `:root` in `docs/style.css` defines `--bg-tertiary`, `--primary-color`, `--bg-card`, `--bg-hover`, `--badge-bg`, and `.badge-eco`.
    - Assert all `target="_blank"` links in `docs/updates.html` contain `rel="noopener"`.
    - Assert `<svg id="historical-sparkline"` in `docs/updates.html` includes `viewBox="0 0 1000 80"`.

---

## 4. Concrete Implementation Instructions

1. Create `tests/test_analytics.py` with comprehensive pytest fixtures and assertions covering `INVARIANT_83_1A` through `INVARIANT_83_1D`.
2. Create `tests/test_wave14_portal.py` covering `INVARIANT_83_2A` through `INVARIANT_83_2D`.
3. Execute `.venv/bin/pytest -v tests/test_analytics.py tests/test_wave14_portal.py` and `.venv/bin/pytest -q` across the full test suite.

---

## 5. Non-Interactive Completion Directive

Complete all implementation steps, verify all tests pass locally, and commit directly without asking open-ended questions so the session cleanly transitions to `Completed`.

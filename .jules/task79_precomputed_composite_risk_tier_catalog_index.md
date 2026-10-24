# Task 79: Precomputed `composite_risk_tier` in Catalog Index (P0)

**Defect:** W14-02 · **Files:** `src/mcp_vulnerabilities/site_builder.py`, `docs/app.js`, `docs/updates.js` · **Wave:** 15

## Problem
`getServerCompositeRisk()` (`docs/app.js` ~L683–710) iterates `server.versions`, but `mcp_catalog_index.json` (built in `site_builder.py` ~L505–545) omits `versions`. Result: every directory card falls back to `static_risk_tier` → `Risk: LOW`, even for servers with CRITICAL CVEs.

## Required Change
1. In `site_builder.py`, while building each `catalog_index` entry, compute the highest advisory severity across vulnerable versions (`CRITICAL > HIGH > MODERATE/MEDIUM > LOW`) and stamp:
   - `highest_cve_severity` (string or `null`)
   - `composite_risk_tier` = max(`static_risk_tier`, `highest_cve_severity`)
2. In `docs/app.js` (and `docs/updates.js` if it has a similar helper), `getServerCompositeRisk()` returns `server.composite_risk_tier` when present, else keeps current fallback logic.
3. The "Static Capability Risk" filter chips must keep filtering on the same tier that the card displays (or document which one is used).

## Acceptance Criteria
- [ ] Every catalog index entry has `composite_risk_tier`; output remains deterministic (`sort_keys=True`).
- [ ] A server with a CRITICAL advisory renders `RISK: CRITICAL` on its directory card.
- [ ] Servers with no advisories keep their static tier.
- [ ] Unit test covering the severity-max helper (may live in Task 82 file).
- [ ] `.venv/bin/pytest -q` no regressions.

## Constraints
Do not run full dataset regeneration in the cloud VM; verify with fixtures. Minimal diff. Coordinate with Task 81 (same file). Non-interactive completion.

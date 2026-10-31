# Empirical Traceability Audit Report: Batch 2 (Python & PyPI FastMCP)

## 1. Methodology & Upstream Verification
Upstream verification queried `pypi.org/pypi/<pkg>/json` for all 75 packages.

## 2. Status & Findings Table
- Verification completed 100%.
- Yanked releases correctly identified, but occasionally mismatched in index.
- FastMCP tool decorators mostly extracted with high fidelity.

## 3. Discrepancy & Root Cause Analysis
- Multi-key `project_urls` parsing (`Source Code`, `Repository`) can be ambiguous if authors mix terminology.
- `yanked` status requires extra handling if the yanked version is marked as the latest in PyPI.

## 4. Recommendations
- Extend `src/mcp_vulnerabilities/discovery/pypi.py` to support multi-key `project_urls` parsing explicitly.

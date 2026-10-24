# Task 81: Latest-Version Analytics & Catalog Tool Ingestion (P1)

**Defect:** W14-05 · **File:** `src/mcp_vulnerabilities/site_builder.py` · **Wave:** 15

## Problem
`versions` are sorted ascending (`_parse_sort_version`, L153/L378), but two places pick `versions[0]` (the **oldest** release):
- L506 — catalog index `tools`, `tools_count`, `tools_sample`
- L651 — analytics capability surface + `required_env_vars` (Secrets Perimeter shows "No secrets data available")

## Required Change
Use the latest version (`versions[-1]`) in both places. Optionally prefer the latest version that has non-empty `tools` if the newest has none — document the choice in a comment.

## Acceptance Criteria
- [ ] Both sites use the latest version; a fixture with `[v0.1 (1 tool), v1.0 (3 tools, env FOO)]` yields `tools_count == 3` and `env_vars["FOO"] == 1`.
- [ ] Deterministic output preserved.
- [ ] `.venv/bin/pytest -q` no regressions (update any test that encoded the old behavior, explaining why).

## Constraints
Coordinate with Task 79 (same file). Fixture-based verification only; no full dataset rebuild in cloud. Non-interactive completion.

# Task 155: Fix Failing GitHub Actions Pipelines (CI, Test Action, Sign Release)

## Objective
Fix all remaining pipeline failures across GitHub Actions workflows:
1. `ci.yml`: Fix `tests/audit/test_traceability_batch2_pypi.py` where `"agents"` (npm package) is mistakenly expected to be a PyPI package in `sample_names`. Replace with `"agent-mcp"`.
2. `test_action.yml`: Fix `src/mcp_vulnerabilities/audit/parsers.py` to extract `--version <val>` or `-v <val>` or `--version=<val>` from python command args. Fix `src/mcp_vulnerabilities/fingerprints/resolver.py` so that bare `"python"` does not inspect `.` (cwd's `pyproject.toml`) and ensure any inspected `pyproject.toml` validates that `project.name` matches the server's package name before returning its version.
3. `sign_release.yml`: Upgrade `sigstore/gh-action-sigstore-python@v2.1.1` to `@v3.0.0` (eliminating deprecated `actions/upload-artifact@v3`). Add `workflow_dispatch:` to `sign_release.yml` and `test_action.yml`.

## Acceptance Criteria
1. `uv run pytest tests/audit/test_traceability_batch2_pypi.py` passes.
2. `mock_vulnerable_config.json` with `{"command": "python", "args": ["-m", "mcp_neo4j_cypher", "--version", "0.1.0"]}` correctly parses version `0.1.0` and flags vulnerability on `mcp-vuln audit --config mock_vulnerable_config.json --severity-threshold HIGH`.
3. Running `FingerprintVersionResolver` on an unpinned python server in cwd does NOT falsely assign `mcp-vulnerabilities`'s version to the target server.
4. `.github/workflows/sign_release.yml` uses `sigstore/gh-action-sigstore-python@v3.0.0` and has `workflow_dispatch:`.
5. `.github/workflows/test_action.yml` has `workflow_dispatch:`.
6. Full test suite `uv run pytest tests/` passes.

# Task: Fix CI Test Failures in daily_sync (Acceptance SBOM & E2E Cross-Repo Sync)

## Objective & Scope
Resolve the 3 test failures identified during the manual GitHub Actions CI run of `Daily MCP Vulnerability Ingestion & Sync`:
1. `tests/test_acceptance_sbom.py::test_acceptance_cyclonedx_audit` and `test_acceptance_cyclonedx_probe` failed with `FileNotFoundError: [Errno 2] No such file or directory: 'uv'`.
2. `tests/test_e2e_cross_repo_sync.py::TestCrossRepoSync::test_fetch_latest_passports_rate_limit` failed because the new fallback in `CrossRepoSyncManager` attempted to download from the live `raw.githubusercontent.com` URL during a local mock server test (`127.0.0.1`), succeeding instead of returning `False`.

## Target Files
1. `src/mcp_vulnerabilities/sync_manager.py`
2. `tests/test_acceptance_sbom.py`
3. `.github/workflows/daily_sync.yml`

## Implementation Details
1. **In `src/mcp_vulnerabilities/sync_manager.py`**:
   - In `CrossRepoSyncManager.__init__`:
     Add parameter `raw_github_url: Optional[str] = "https://raw.githubusercontent.com/jmartynov/mcp-fingerprints/main/passports.json.gz"` and store as `self.raw_github_url = raw_github_url`.
   - In `fetch_latest_passports(self, github_token: Optional[str] = None) -> bool`:
     When falling back to raw download:
     - Check:
       ```python
       if not self.raw_github_url:
           return False
       if ("127.0.0.1" in self.github_api_url or "localhost" in self.github_api_url) and "githubusercontent.com" in self.raw_github_url:
           logger.info("Custom local API host detected; skipping external raw fallback.")
           return False
       ```
     - Use `self.raw_github_url` instead of hardcoded string.
2. **In `tests/test_acceptance_sbom.py`**:
   - Import `shutil`.
   - Use `cmd = ["uv", "run", "mcp-vuln"] if shutil.which("uv") else [sys.executable, "-m", "mcp_vulnerabilities.cli"]` in both `test_acceptance_cyclonedx_audit` and `test_acceptance_cyclonedx_probe`.
3. **In `.github/workflows/daily_sync.yml`**:
   - In the `Install dependencies` step, install `uv`:
     ```yaml
     - name: Install dependencies
       run: |
         python -m pip install --upgrade pip
         pip install -e ".[dev]" uv
     ```
4. **Verification**:
   - Run `pytest tests/test_acceptance_sbom.py tests/test_e2e_cross_repo_sync.py -v` to confirm all 3 tests pass.
   - Run full test suite `pytest tests/ -q --tb=short` to ensure all 277 tests pass.

## Non-Interactive Completion Directive
Apply all fixes directly and run tests. Do not ask open-ended questions. Cleanly transition the remote VM session to Completed.

### Task: GitHub API Token & Rate-Limit Protection

#### 1. Architectural Context & Problem Analysis:
The MCP Vulnerability Ingestion Pipeline continuously polls upstream GitHub endpoints for new security occurrences:
* **GitHub Security Advisories (GHSA)** REST API: `https://api.github.com/advisories`
* **CVEListV5 Commit Delta**: `https://api.github.com/repos/CVEProject/cvelistV5/commits`

Currently, both feeds dispatch unauthenticated HTTP requests (`pipeline.py:242` and `pipeline.py:286`). GitHub enforces a strict threshold of **60 requests per hour** for unauthenticated clients per public IP address. In high-frequency sync runs, CI execution environments (where runners share public GitHub egress IPs), or when traversing multi-page advisory streams, unauthenticated requests rapidly trigger HTTP 403 Forbidden (`API rate limit exceeded`) or HTTP 429 Too Many Requests, causing silent synchronization halts or partial feed ingestion.

Injecting an optional `GITHUB_TOKEN` or `GH_TOKEN` immediately elevates the quota from 60 to **5,000 requests per hour**, ensuring reliable, enterprise-grade ingestion.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/pipeline.py`:
  * Lines 240–280: `_query_ghsa_api()` headers construction.
  * Lines 285–336: `_query_cvelist_delta()` commits headers and raw file fetchers.
* `.github/workflows/daily_sync.yml`:
  * Lines 38–40: GitHub Actions step `Run MCP Ingestion & Normalization Pipeline`.

#### 3. Engineering & Implementation Blueprint:
1. In `src/mcp_vulnerabilities/pipeline.py`, implement an authenticated header factory:
   ```python
   def _get_github_headers() -> dict[str, str]:
       headers = {
           "User-Agent": "McpVulnerabilities/1.0 (Security Research; +https://github.com/JMartynov/mcp-vulnerabilities)",
           "Accept": "application/vnd.github.v3+json",
       }
       token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
       if token:
           headers["Authorization"] = f"Bearer {token.strip()}"
       return headers
   ```
2. Refactor all outgoing GitHub API calls in `pipeline.py` to use `_get_github_headers()`:
   * GHSA pagination loop and initial request.
   * CVEListV5 commits delta listing and individual raw commit blob fetches.
3. In `.github/workflows/daily_sync.yml`, expose the default workflow token to the step environment:
   ```yaml
   - name: Run MCP Ingestion & Normalization Pipeline
     env:
       GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
     run: |
       python -m mcp_vulnerabilities.cli sync --live-api
   ```

#### 4. Guardrails & Security Invariants:
* **Zero Credential Leakage**: Never log the token value, dump authorization headers into debug output, or serialize tokens into error strings.
* **Graceful Degradation**: If `GITHUB_TOKEN` is unset or empty, the pipeline must continue without raising exceptions, falling back to unauthenticated requests.
* **Transient Error Handling**: Handle HTTP 403 rate limit responses with clear user-facing diagnostics indicating rate limit exhaustion and token configuration guidance.

#### 5. Acceptance Criteria & Test Plan:
- [ ] Outgoing GitHub API requests include `Authorization: Bearer <token>` when `GITHUB_TOKEN` or `GH_TOKEN` is set in the environment.
- [ ] Requests succeed without authorization headers when tokens are unset.
- [ ] Unit test in `tests/test_osv_pipeline.py` uses `unittest.mock` to assert header presence on requests to `api.github.com`.
- [ ] Integration test verifies that `daily_sync.yml` passes secret injection syntax validation.
- [ ] 100% of existing tests pass (`pytest -v`).

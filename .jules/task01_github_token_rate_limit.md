### Task: GitHub API Token & Rate-Limit Protection

#### 1. Overview & Context:
Both GHSA API ingestion and CVEListV5 commit delta traversal send HTTP requests to `api.github.com`. Unauthenticated requests are strictly capped by GitHub at **60 requests per hour** per IP address. In high-frequency runs, parallel testing, or CI runners, this risks hitting HTTP 403 / 429 rate limits. Authenticated requests with `GITHUB_TOKEN` receive **5,000 requests per hour**.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/pipeline.py`:
  * Lines 242–255: GHSA API request headers (`urllib.request.Request`).
  * Lines 287–310: CVEListV5 commit delta headers.
* `.github/workflows/daily_sync.yml`:
  * Lines 38–40: Ingestion step `Run MCP Ingestion & Normalization Pipeline`.

#### 3. Implementation Details:
1. In `src/mcp_vulnerabilities/pipeline.py`:
   - Implement `_get_github_headers() -> dict[str, str]` helper:
     ```python
     def _get_github_headers() -> dict[str, str]:
         headers = {
             "User-Agent": "McpVulnerabilities/1.0",
             "Accept": "application/vnd.github.v3+json",
         }
         token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
         if token:
             headers["Authorization"] = f"Bearer {token}"
         return headers
     ```
   - Use `_get_github_headers()` in all outgoing GitHub REST API calls (`ghsa_url`, pagination requests, and `cve_delta_url`).
2. In `.github/workflows/daily_sync.yml`:
   - Pass `GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}` in the environment of the sync step.

#### 4. Strict Guardrails:
- Gracefully fall back to unauthenticated requests when no token is present; never raise exceptions due to missing token.
- Never log or leak the token in debug outputs or error messages.

#### 5. Acceptance Criteria & Tests:
- [ ] Outgoing GitHub API requests include `Authorization: Bearer <token>` when `GITHUB_TOKEN` is set in the environment.
- [ ] Requests succeed without headers when `GITHUB_TOKEN` is unset.
- [ ] Unit test in `tests/test_osv_pipeline.py` verifies header injection using `unittest.mock`.
- [ ] All tests pass with `pytest`.

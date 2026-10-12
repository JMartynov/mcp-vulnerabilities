### Task: NVD 2.0 API Ingestion Stream & Converter Pipeline

#### 1. Architectural Context & Purpose:
Currently, the multi-source vulnerability pipeline ingests from GitHub Security Advisories (GHSA), CVEListV5 git commits, OSV.dev, and curated markdown feeds.
The NIST National Vulnerability Database (NVD) 2.0 REST API (`https://services.nvd.nist.gov/rest/json/cves/2.0`) is the canonical authoritative registry for CVE analysis, CVSS vector scoring, and CWE weakness classification.
Adding native live ingestion against NVD 2.0 enables capturing CVEs the moment NIST publishes them, often before downstream aggregators index them.
This task connects `NvdConverter` in `converters/nvd.py` to the ingestion pipeline, handles NVD rate-limiting (up to 50 requests/30s with API key, 5 requests/30s without), implements cursor pagination, and filters records using `McpRelevanceFilter`.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/converters/nvd.py`: `NvdConverter` (already implements NVD JSON -> `OsvVulnerability`).
* `src/mcp_vulnerabilities/pipeline.py`: Main pipeline execution, state tracking, and API sync.
* `src/mcp_vulnerabilities/filter.py`: `McpRelevanceFilter`.
* `src/mcp_vulnerabilities/cli.py`: Subcommand `sync` arguments.
* `.github/workflows/daily_sync.yml`: CI daily pipeline workflow.

#### 3. Engineering & Implementation Blueprint:
1. **In `src/mcp_vulnerabilities/pipeline.py`**:
   - Add helper `_get_nvd_headers() -> dict[str, str]`:
     - Reads `NVD_API_KEY` from environment.
     - If present, attaches `apiKey: <token>` and `User-Agent: mcp-vulnerabilities-ingest/1.0`.
   - Implement `_sync_nvd_api(self, keywords: tuple[str, ...] = ("modelcontextprotocol", "mcp server"), results_per_page: int = 100) -> list[OsvVulnerability]`:
     - Base URL: `https://services.nvd.nist.gov/rest/json/cves/2.0`
     - For each keyword, query `keywordSearch={keyword}&resultsPerPage={results_per_page}&startIndex={start_index}`.
     - Rate-limiting guard:
       - If `NVD_API_KEY` is present, delay 0.65s between requests.
       - If unauthenticated, delay 6.0s between requests.
       - Catch HTTP 403/429 and retry with exponential backoff (up to 3 retries).
     - Parse JSON response:
       - Extract `vulnerabilities` array.
       - Convert each CVE item using `NvdConverter.from_dict(vuln)`.
       - Filter with `McpRelevanceFilter.is_mcp_relevant(vuln.summary, vuln.details, package_name)`.
     - Support pagination: loop until `startIndex + resultsPerPage >= totalResults`.
   - Update `McpVulnerabilityPipeline.run()`:
     - Add argument `include_nvd_api: bool = False`.
     - When `include_live_api` or `include_nvd_api` is True, execute `_sync_nvd_api()`.
     - Update checkpoint in `sync_state.json` under source `"nvd_api"`.
2. **In `src/mcp_vulnerabilities/cli.py`**:
   - Add argument `--nvd-api` to `sync_p` parser (`action="store_true"`, help="Query live NIST NVD 2.0 API").
   - In `args.command == "sync"` handler, pass `include_nvd_api=args.live_api or args.nvd_api`.
3. **In `.github/workflows/daily_sync.yml`**:
   - In the `Run MCP Ingestion & Normalization Pipeline` step, add:
     ```yaml
     env:
       GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
       NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
     ```
4. **Unit & Integration Tests**:
   - Create `tests/test_nvd_pipeline.py`:
     - Test mock NVD 2.0 API responses (single page, multi-page pagination).
     - Test `_get_nvd_headers()` with and without `NVD_API_KEY`.
     - Test rate-limiting backoff on mock HTTP 429.
     - Test MCP relevance filtering of incoming NVD CVE records.

#### 4. Guardrails & Security Invariants:
* **Zero Leakage**: Never log or print the `NVD_API_KEY` in logs or stack traces.
* **Fail-Safe Operation**: If NVD API is unavailable or returns 5xx/429, log a warning and continue syncing other sources without crashing the pipeline.

#### 5. Acceptance Criteria:
- [ ] `_sync_nvd_api()` connects to NVD 2.0 REST API, parses records using `NvdConverter`, and filters with `McpRelevanceFilter`.
- [ ] Supports `NVD_API_KEY` header authentication with 0.65s rate limiting, and unauthenticated fallback with 6s rate limiting.
- [ ] CLI `sync` supports `--nvd-api` flag and includes NVD when `--live-api` is passed.
- [ ] `.github/workflows/daily_sync.yml` includes `NVD_API_KEY` secret wiring.
- [ ] Unit tests in `tests/test_nvd_pipeline.py` pass with 100% assertions satisfied.

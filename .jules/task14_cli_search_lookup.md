### Task: Direct Vulnerability Search & Inspection CLI (cli search / cli lookup)

#### 1. Architectural Context & Purpose:
Currently, the `mcp-vulnerabilities` CLI supports `audit` (which requires an AI client config file or a specific package string like `@package@version`). However, security engineers, DevOps personnel, and researchers need ad-hoc interactive search capabilities directly from their terminal:
* Searching by advisory ID (e.g. `mcp-vuln lookup GHSA-w24r-9vj3-v4wh` or `CVE-2024-51439`).
* Searching by package name or MCP tool name (e.g. `mcp-vuln search postgres` or `mcp-vuln search cypher_query`).
* Filtering by severity threshold (e.g. `mcp-vuln search --min-severity HIGH --ecosystem npm`).
* Outputting in human-readable formatted terminal tables or raw JSON for piping into `jq`.

Adding dedicated `search` and `lookup` subcommands significantly enhances developer experience and triage workflows.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/cli.py`: Subcommand definitions for `search` and `lookup`.
* `src/mcp_vulnerabilities/audit/matcher.py`: In-memory querying and index lookup.
* `data/vulnerabilities/index.json`: Primary search index with fields `id`, `aliases`, `summary`, `details`, `affected`, `severity`, `vulnerable_tools`.
* `src/mcp_vulnerabilities/models.py`: `OsvVulnerability` model.

#### 3. Engineering & Implementation Blueprint:
1. **In `src/mcp_vulnerabilities/audit/matcher.py`**:
   - Implement `search(query: str, min_severity: Optional[str] = None, ecosystem: Optional[str] = None) -> List[SearchResult]`.
     - Match query against advisory `id`, `aliases` (CVEs), package names in `affected`, `vulnerable_tools`, and summary text (case-insensitive substring match).
     - Filter by minimum severity CVSS score (LOW: 0.1, MEDIUM: 4.0, HIGH: 7.0, CRITICAL: 9.0).
   - Implement `get_advisory(advisory_id: str) -> Optional[OsvVulnerability]`.
     - Fast dictionary lookup by exact ID or alias from `index.json` or snapshot.
2. **In `src/mcp_vulnerabilities/cli.py`**:
   - Add subcommand `search`:
     ```bash
     mcp-vuln search <query> [--min-severity HIGH] [--ecosystem npm] [--format table|json]
     ```
   - Add subcommand `lookup`:
     ```bash
     mcp-vuln lookup <id_or_alias> [--format table|json]
     ```
   - Render clean terminal output with color-coded severity badges, affected package versions, vulnerable tool names, and remediation guidance.
3. **Unit Tests**:
   - Create `tests/test_cli_search.py` verifying keyword search, alias lookup, severity filtering, and JSON/table formatting.

#### 4. Guardrails & Security Invariants:
* **Zero Crash on Missing Query**: Empty queries or non-existent IDs must output clean messages and exit with code 0 or 1 without throwing unhandled exceptions.
* **Snapshot & Directory Dual-Mode**: Must work seamlessly using either the local `data/vulnerabilities` directory or `vulnerabilities.json.gz`.

#### 5. Acceptance Criteria:
- [ ] Running `cli lookup <GHSA_OR_CVE_ID>` prints full advisory metadata, affected ranges, and vulnerable tools.
- [ ] Running `cli search <keyword>` returns matching advisories filtered by package name, tool, or summary.
- [ ] `--min-severity` correctly excludes advisories below the specified threshold.
- [ ] `--format json` outputs valid parseable JSON suitable for piping to `jq`.
- [ ] Unit tests in `tests/test_cli_search.py` pass with 100% assertions satisfied.

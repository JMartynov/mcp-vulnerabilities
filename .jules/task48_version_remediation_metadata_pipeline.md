# Task 48: MCP Server Multi-Version Vulnerability & Remediation Metadata Pipeline (P0)

## 1. Architectural Context & Technical Objective
To power the interactive Security Explorer, the system must maintain more than just flat OSV advisories. Users need to inspect any tracked MCP server across its entire release history, see which versions contain vulnerabilities, and receive explicit guidance on **which version to update to** in order to resolve identified issues.

This task extends the correlation engine (`src/mcp_vulnerabilities/fingerprints/correlator.py`) and site builder (`src/mcp_vulnerabilities/site_builder.py`) to:
1. Aggregate and sort all known released versions for each MCP server (sourced from PyPI, npm, GitHub tags, and passport metadata).
2. Map each release version against OSV semver ranges (`introduced`, `fixed`) to determine per-version vulnerability status (`is_vulnerable`, list of active CVE/GHSA IDs, highest severity).
3. Compute the optimal safe remediation target version (`recommended_version`): the lowest patched version that resolves the vulnerability, or the latest known secure release if no intermediate patch exists.
4. Synthesize ecosystem-aware remediation update commands (e.g. `npm install @org/server@^1.4.0` or `pip install mcp-server>=2.1.0`).
5. Output structured version-matrix metadata into `docs/data/mcp_catalog_index.json` and server shards.

---

## 2. Target Files & Documentation
- `src/mcp_vulnerabilities/fingerprints/correlator.py`
- `src/mcp_vulnerabilities/site_builder.py`
- `src/mcp_vulnerabilities/models.py` (or data structures)
- `tests/test_version_remediation_pipeline.py`
- `docs/version_remediation_specification.md`
- `docs/tasks/README.md`

---

## 3. Acceptance Scenarios & Criteria

### Scenario 1: Multi-Version Aggregation & SemVer Sorting
- [ ] GIVEN an MCP server tracked in passports or catalog index (e.g. `mcp-server-git`, `@modelcontextprotocol/server-filesystem`)
- [ ] WHEN the correlation pipeline processes the server
- [ ] THEN it gathers all published versions and sorts them according to Semantic Versioning (SemVer) order (e.g. `["0.1.0", "0.1.1", "0.2.0", "1.0.0"]`).

### Scenario 2: Per-Version Vulnerability Mapping
- [ ] GIVEN an MCP server with versions `["1.0.0", "1.0.1", "1.1.0", "1.2.0"]` and an OSV advisory affecting `< 1.1.0`
- [ ] WHEN the pipeline evaluates version status
- [ ] THEN versions `1.0.0` and `1.0.1` are tagged with `is_vulnerable: true` and linked to the specific advisory ID(s)
- [ ] AND versions `1.1.0` and `1.2.0` are tagged with `is_vulnerable: false` (clean / unaffected).

### Scenario 3: Remediation Target Calculation
- [ ] GIVEN a user inspecting a vulnerable version (e.g. `1.0.0`)
- [ ] WHEN the pipeline calculates remediation metadata
- [ ] THEN `recommended_version` is identified as `1.1.0` (the minimum safe patched release)
- [ ] AND if no fixed version exists in upstream advisories, it is tagged as `no_fix_available: true` with workaround/mitigation advice.

### Scenario 4: Ecosystem-Aware Upgrade Command Generation
- [ ] GIVEN an identified server with a known ecosystem (`npm`, `pypi`, `docker`)
- [ ] WHEN generating remediation commands for a safe target version
- [ ] THEN for `npm`: emits `npm install <package>@^<target_version>`
- [ ] AND for `pypi`: emits `pip install --upgrade <package>>=<target_version>`
- [ ] AND for `docker`: emits `docker pull <image>:<target_version>`.

### Scenario 5: Sharded JSON Payload Optimization
- [ ] GIVEN 5,000+ servers in the catalog
- [ ] WHEN building static site data artifacts in `docs/data/`
- [ ] THEN the index file contains lightweight summaries and sharded detail files contain the full version matrices, maintaining gzip transfer under performance budgets.

---

## 4. Implementation Steps
- [ ] 1. Enhance `src/mcp_vulnerabilities/fingerprints/correlator.py` to index all known versions per server.
- [ ] 2. Implement `resolve_version_status(server, version)` evaluating OSV affected ranges.
- [ ] 3. Implement `compute_remediation_target(server, current_version)` determining the safe target version and upgrade command.
- [ ] 4. Update `site_builder.py` to write `version_matrix` and `remediation` fields into `docs/data/`.
- [ ] 5. Write unit tests in `tests/test_version_remediation_pipeline.py` verifying SemVer sorting, edge cases (yanked versions, pre-releases, unpatched vulns), and remediation targets.

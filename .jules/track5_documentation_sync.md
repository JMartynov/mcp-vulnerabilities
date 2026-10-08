### Task: Synchronize System Architecture, Specification, and Implementation Documentation

#### 1. Context & Contract:
Update `docs/SPECIFICATION.md` and create `docs/IMPLEMENTATION.md`:
1. In `docs/SPECIFICATION.md`:
   - Add Section 4: "Live Advisory Ingestion & Checkpoint Protocol" detailing the `Link` header pagination and `since=<ISO_TIMESTAMP>` query parameters for GitHub advisories, and commit SHA traversal for CVEListV5.
   - Add Section 5: "Version Resolution & Semver Invalidation" explaining `resolve_package_version()` for PyPI and semver delta tracking in `data/mcp_catalog_state.json`.
   - Add Section 6: "Historical Search Index Invariants" defining the pre-loading contract where incremental pipeline executions preserve all existing records in `data/vulnerabilities/index.json`.
   - Add Section 7: "OSV 1.6 Range Integrity & Grouped Deduplication Rules" documenting how overlapping ranges are partitioned by `(type, repo)` to prevent duplicate adjacent `fixed` events.
2. Create `docs/IMPLEMENTATION.md`:
   - Provide an end-to-end architecture blueprint covering:
     - Multi-registry discovery (`mcp_vulnerabilities.discovery`)
     - Multi-source ingestion & normalization pipeline (`mcp_vulnerabilities.pipeline`)
     - State machines (`SyncStateManager` and `McpCatalogState`)
     - The Acceptance Test Suite guide (`tests/test_acceptance_*.py`)
3. Update `README.md` to reference the new acceptance test commands (`pytest -v tests/test_acceptance_*`) and architecture documentation.

#### 2. Strict Guardrails:
- Maintain clean Markdown formatting and GitHub Flavored Markdown alerts (`> [!NOTE]`, `> [!IMPORTANT]`).
- Ensure all relative links between documents are valid.

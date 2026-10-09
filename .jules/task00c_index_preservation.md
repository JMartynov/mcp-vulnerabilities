### Task: Historical Advisory Pre-Loading & Index Preservation (Foundational 00-C)

#### 1. Architectural Context & Purpose:
The search index (`data/vulnerabilities/index.json`) is the primary fast-lookup mechanism used by the CLI auditor and Web Explorer. Previously, `pipeline.py` initialized its ingestion buffer as an empty list (`collected = []`). During incremental sync runs where only 2 new advisories were returned by delta feeds, `pipeline.py` wrote out an index containing only those 2 advisories, overwriting and wiping out 517+ previously curated historical vulnerabilities.
This task enforces an immutable pre-load invariant: all existing advisory records on disk must be loaded into memory before deduplication, merging, and index generation.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/pipeline.py`: Method `_load_existing_records()` and `run()`.
* `src/mcp_vulnerabilities/deduplicator.py`: Class `VulnerabilityDeduplicator`.
* `tests/test_acceptance_index_preservation.py`: Acceptance test suite validating index preservation across incremental sync cycles.

#### 3. Engineering & Implementation Blueprint:
1. **Pre-loading Existing Disk Records**:
   - In `McpVulnerabilityPipeline.run()`, scan `data/vulnerabilities/*.json` prior to invoking external data feeds.
   - Parse each JSON file into an `OsvVulnerability` model and populate `collected = self._load_existing_records()`.
2. **Deterministic Deduplication & Merge**:
   - Merge freshly ingested records with existing records using `VulnerabilityDeduplicator.merge_records()`.
   - Update modified records while preserving untouched historical records.
3. **Index Atomic Write**:
   - Generate `data/vulnerabilities/index.json` containing the total union of all historical and newly added advisories.
   - Write via atomic temporary file (`index.json.tmp`) to prevent index corruption during abrupt termination.

#### 4. Guardrails & Security Invariants:
* **Monotonic Count Invariant**: Incremental runs must NEVER decrease the total count in `index.json`. Total count must be $\ge$ previous count.
* **Schema Validation**: Every pre-loaded record must conform to the OSV 1.6 specification.

#### 5. Acceptance Criteria:
- [x] `pipeline.py` loads existing advisories from disk before running sync streams.
- [x] Incremental runs with low or zero delta results retain 100% of historical advisories in `index.json`.
- [x] Atomic write prevents corrupt or partial index files on disk.
- [x] Acceptance tests in `tests/test_acceptance_index_preservation.py` assert record count preservation across simulated incremental runs.

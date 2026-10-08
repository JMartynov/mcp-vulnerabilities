### Task: Preserve Historical Advisories and Prevent Index Overwrite in Incremental Sync

#### 1. Context & Contract:
In `src/mcp_vulnerabilities/pipeline.py`:
1. Historical Advisory Pre-loading:
   - In `McpVulnerabilityPipeline.run()`:
     Before running converters, load existing advisories from `self.output_dir / "*.json"` (skipping `index.json` and `sync_state.json`) and initialize `collected` (or a historical list) with them so existing records are not lost.
   - When new/updated advisories arrive from GHSA, CVE, or OSV, `OsvDeduplicator.deduplicate_and_merge()` merges new advisories with existing ones.
   - This ensures incremental runs with only 1 or 2 new items do NOT overwrite `index.json` to `count: 2`, preserving all 500+ historical advisories.
2. In `cvelist_v5` ingestion (`pipeline.py:185`):
   - Rather than strictly skipping `file_rel_str <= last_marker`, ensure that file modifications or amended historical CVEs are not permanently blocked if their contents or modification times changed.

#### 2. Strict Guardrails:
- Zero unauthorized dependencies.
- Preserve atomic file writes and schema validation.

#### 3. Testing:
- Add a test in `tests/test_osv_pipeline.py` verifying that an incremental run with 1 new item retains all existing items in `index.json`.
- All tests must pass with `pytest`.

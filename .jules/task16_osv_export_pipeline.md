### Task: Upstream OSV.dev Exporter & Ecosystem Contribution Pipeline

#### 1. Architectural Context & Purpose:
The repository curates 519+ vulnerabilities specifically affecting Model Context Protocol implementations, servers, tools, and clients. Google's Open Source Vulnerabilities (OSV.dev) database operates as an open distributed standard where ecosystems contribute canonical advisory datasets (e.g. `PyPI`, `npm`, `Go`, `crates.io`).
Building an automated export and packaging pipeline conforming to OSV.dev's data ingestion specification enables `mcp-vulnerabilities` to serve as the upstream canonical authority for the `MCP` ecosystem, contributing advisories back to global security data lakes.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/snapshot.py`: Snapshot compilation.
* `src/mcp_vulnerabilities/validator.py`: `OsvValidator`.
* `src/mcp_vulnerabilities/cli.py`: CLI subcommand `export-osv`.
* `.github/workflows/daily_sync.yml`: Hooking the automated export into daily sync.

#### 3. Engineering & Implementation Blueprint:
1. **OSV.dev Batch Export Format**:
   - OSV.dev requires an `all.zip` or individual JSON files in an ecosystem-specific bucket/release structure, alongside an `ecosystem.json` metadata descriptor.
   - Implement `export_osv_bucket(data_dir: Path, output_dir: Path)`:
     - Normalizes all advisory records ensuring required OSV 1.6 fields: `schema_version`, `id`, `modified`, `published`, `summary`, `details`, `affected` with valid ecosystem ranges.
     - Generates `dist/osv/all.zip` containing all canonical advisories.
     - Generates `dist/osv/manifest.json` with record count, SHA-256 hashes, and last modified timestamps.
2. **In `src/mcp_vulnerabilities/cli.py`**:
   - Add subcommand `export-osv`:
     ```bash
     mcp-vuln export-osv --data-dir data/vulnerabilities --output-dir dist/osv
     ```
3. **Automated Publishing in CI**:
   - In `.github/workflows/daily_sync.yml` or a dedicated release workflow, publish `all.zip` and manifest to GitHub Releases as an attachable asset.
4. **Unit Tests**:
   - In `tests/test_snapshot.py`, add `test_export_osv_bucket()` asserting archive integrity, manifest schema conformance, and zip contents.

#### 4. Guardrails & Security Invariants:
* **Schema Strictness**: All exported records in `all.zip` must pass strict OSV 1.6 schema validation with 0 warnings or errors.
* **Deterministic Compression**: Archive creation must use deterministic timestamps to ensure reproducible builds.

#### 5. Acceptance Criteria:
- [ ] Running `cli export-osv` generates `all.zip` and `manifest.json`.
- [ ] Every advisory in the archive conforms to OSV 1.6 JSON schema.
- [ ] Manifest accurately lists SHA-256 checksums and total advisory count.
- [ ] Unit tests in `tests/test_snapshot.py` assert export archive integrity and metadata.

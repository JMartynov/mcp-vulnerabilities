### Task: Automated Periodic Snapshot Distribution Workflow (snapshot_release.yml)

#### 1. Architectural Context & Purpose:
Downstream consumers, enterprise DevSecOps teams, and air-gapped enclaves need convenient access to pre-compiled vulnerability database snapshots (`vulnerabilities.json.gz`, `all.zip`, and `mcp-offline.tar.gz`) without having to clone the repository or execute local Python pipelines.
Currently, daily ingestion runs update files in git, but there is no automated mechanism attaching downloadable release assets to GitHub Releases on a recurring schedule.
This task creates an automated bi-weekly / on-demand GitHub Actions workflow (`.github/workflows/snapshot_release.yml`) that compiles fresh snapshots, generates an airgap enterprise bundle, exports the OSV dataset bucket, generates cryptographically verifiable SHA-256 checksums, and tags and publishes official snapshot releases with attached assets.

#### 2. Codebase References:
* `.github/workflows/snapshot_release.yml`: Target automated release workflow.
* `src/mcp_vulnerabilities/snapshot.py`: Snapshot and airgap export logic.
* `src/mcp_vulnerabilities/cli.py`: CLI commands `snapshot`, `export-airgap`, `export-osv`.
* `README.md`: Public documentation for snapshot downloads.

#### 3. Engineering & Implementation Blueprint:
1. **Create `.github/workflows/snapshot_release.yml`**:
   - Triggers:
     - Scheduled cron: `0 2 1,15 * *` (At 02:00 UTC on the 1st and 15th of every month).
     - Manual dispatch: `workflow_dispatch`.
   - Permissions:
     - `contents: write`
   - Jobs:
     - `publish-snapshot`:
       - Runs on `ubuntu-latest`.
       - Steps:
         - Checkout repository (`actions/checkout@v4`).
         - Set up Python 3.12 (`actions/setup-python@v5`, `cache: pip`).
         - Install dependencies: `pip install -e .`.
         - Compile snapshot: `python -m mcp_vulnerabilities.snapshot data/vulnerabilities vulnerabilities.json.gz`.
         - Export airgap bundle: `python -m mcp_vulnerabilities.cli export-airgap --output dist/mcp-offline.tar.gz`.
         - Export OSV dataset: `python -m mcp_vulnerabilities.cli export-osv --output-dir dist/osv`.
         - Generate SHA-256 checksums:
           ```bash
           mkdir -p dist
           sha256sum vulnerabilities.json.gz dist/mcp-offline.tar.gz dist/osv/all.zip dist/osv/manifest.json > dist/SHA256SUMS.txt
           ```
         - Extract advisory metrics (total count, date) to construct release title and notes.
         - Tag and create release using `gh release create`:
           ```bash
           TAG_NAME="snapshot-$(date +'%Y.%m.%d')"
           gh release create "$TAG_NAME" \
             --title "Database Snapshot: $(date +'%B %d, %Y')" \
             --notes-file dist/RELEASE_NOTES.md \
             vulnerabilities.json.gz \
             dist/mcp-offline.tar.gz \
             dist/mcp-offline.tar.gz.sha256 \
             dist/osv/all.zip \
             dist/osv/manifest.json \
             dist/SHA256SUMS.txt
           ```
2. **In `README.md`**:
   - Add a "Snapshot Downloads & Mirrors" section with direct links to the latest GitHub Release assets and verification commands:
     ```bash
     curl -sL https://github.com/JMartynov/mcp-vulnerabilities/releases/latest/download/vulnerabilities.json.gz -o vulnerabilities.json.gz
     ```
3. **Validation**:
   - Validate YAML syntax and action execution logic.

#### 4. Guardrails & Security Invariants:
* **Integrity Guarantee**: Every published release MUST include `SHA256SUMS.txt` listing the exact SHA-256 checksums of all uploaded archive files.
* **Deterministic Tagging**: Release tags must follow the format `snapshot-YYYY.MM.DD`.

#### 5. Acceptance Criteria:
- [ ] `.github/workflows/snapshot_release.yml` is created and passes YAML schema validation.
- [ ] Workflow compiles `vulnerabilities.json.gz`, `mcp-offline.tar.gz`, `all.zip`, and `SHA256SUMS.txt`.
- [ ] GitHub Release is created with informative release notes and attached assets.
- [ ] `README.md` documents how to download and verify latest database snapshots.

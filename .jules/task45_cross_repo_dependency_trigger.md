# Task 45: Upstream Fingerprints Dependency & Cross-Repo Auto-Release Trigger (P0)

## Objective & Scope
`mcp-vulnerabilities` is dependent on two distinct upstream data sources:
1. External OSV/NVD/CVE security advisories (`data/vulnerabilities/`)
2. Upstream MCP server fingerprints and tool schemas from `mcp-fingerprints` (`data/passports.json.gz`)

Whenever `mcp-fingerprints` publishes a new release (or updates `passports.json.gz`), `mcp-vulnerabilities` must automatically ingest the updated passports, re-correlate server and version security profiles, bump its own release version (`vX.Y.Z`), update `site_builder` and `updates_builder` datasets, and publish to PyPI.

## Target Files & Workflows (mcp-vulnerabilities)
1. `.github/workflows/daily_sync.yml`:
   - Add `repository_dispatch: types: [upstream_fingerprints_updated]` to `on:`.
   - Ensure `VULN_CHANGES` specifically accounts for `data/passports.json.gz` changes to trigger version bump, tagging, release creation, and PyPI publishing.
2. `src/mcp_vulnerabilities/sync_manager.py`:
   - Harden `CrossRepoSyncManager.fetch_latest_passports`: try GitHub release asset download first, and if missing or rate-limited, fallback to downloading from `https://raw.githubusercontent.com/jmartynov/mcp-fingerprints/main/passports.json.gz`.
3. `tests/test_cross_repo_sync_and_trigger.py`:
   - Test release asset download, raw fallback, and workflow YAML trigger structure.
4. Documentation:
   - `README.md`, `docs/SPECIFICATION.md`, and `docs/IMPLEMENTATION.md`: Document the two upstream data sources and the reactive dispatch release pipeline.
5. `docs/reviews/review_task45.md`: EULIS review proposal.

## Implementation Details
1. **In `src/mcp_vulnerabilities/sync_manager.py`**:
   - In `fetch_latest_passports(self, github_token: Optional[str] = None) -> bool`:
     - Query `https://api.github.com/repos/jmartynov/mcp-fingerprints/releases/latest`.
     - If asset `passports.json.gz` is found, download it.
     - If asset is not found, or an HTTP error (403 rate limit, 404, etc.) occurs, fall back to:
       `https://raw.githubusercontent.com/jmartynov/mcp-fingerprints/main/passports.json.gz`.
     - Write the downloaded stream to `self.target_path` and return `True`.
     - If both fail, log error and return `False`.
2. **In `.github/workflows/daily_sync.yml`**:
   - Ensure `on:` contains:
     ```yaml
     on:
       schedule:
         - cron: "0 3 * * *"
       workflow_dispatch:
       repository_dispatch:
         types: [upstream_fingerprints_updated]
       push:
         paths:
           - "tests/fixtures/osv/**"
           - "src/mcp_vulnerabilities/**"
     ```
   - Ensure `VULN_CHANGES` checks `data/passports.json.gz`:
     ```bash
     VULN_CHANGES=$(git status --porcelain data/vulnerabilities/ data/passports.json.gz data/mcp_servers.json | grep -v "sync_state.json" | grep -v "index.json" || true)
     ```
3. **In `tests/test_cross_repo_sync_and_trigger.py`**:
   - Test mock release with asset -> succeeds.
   - Test mock release without asset -> falls back to raw URL -> succeeds.
   - Test mock failure of both -> returns False.
   - Test `.github/workflows/daily_sync.yml` contains `repository_dispatch` and `upstream_fingerprints_updated`.
4. **Documentation**:
   - Update `README.md`, `docs/SPECIFICATION.md`, and `docs/IMPLEMENTATION.md` explaining the dual upstream data architecture: external advisories + `mcp-fingerprints` passports, and how `upstream_fingerprints_updated` triggers immediate downstream sync and PyPI release.

## Non-Interactive Completion Directive
Finalize all file modifications and unit tests directly. Do not stop to prompt the user or ask open-ended questions. Cleanly transition the remote VM session to Completed.

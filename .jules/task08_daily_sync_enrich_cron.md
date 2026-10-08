### Task: Automated Catalog Enrichment Cron in CI

#### 1. Architectural Context & Purpose:
We developed `CatalogVersionEnricher` and the CLI subcommand `python -m mcp_vulnerabilities.cli enrich --limit N --workers W`. However, the scheduled GitHub Actions workflow `.github/workflows/daily_sync.yml` currently runs multi-registry discovery and live API sync without triggering the enrichment pass.
Adding an automated enrichment step ensures that 500 unversioned PyPI packages are backfilled with release versions every night, continuously improving semver change detection without manual intervention.

#### 2. Codebase References:
* `.github/workflows/daily_sync.yml`: Lines 33–40 (Discovery and Ingestion steps).
* `src/mcp_vulnerabilities/cli.py`: Subcommand `enrich`.
* `data/mcp_servers.json`: Target catalog file updated by enrichment.

#### 3. Implementation Details:
1. In `.github/workflows/daily_sync.yml`:
   Add step between discovery and sync:
   ```yaml
   - name: Run Asynchronous Catalog Version Enrichment
     run: |
       python -m mcp_vulnerabilities.cli enrich --catalog-file data/mcp_servers.json --limit 500 --workers 10
   ```
2. In git staging step (line 59):
   Ensure `data/mcp_servers.json` is staged so enriched package versions are committed back to `main`.

#### 4. Acceptance Criteria:
- [ ] `.github/workflows/daily_sync.yml` includes the automated `enrich` step.
- [ ] Enriched `data/mcp_servers.json` is staged and committed during daily sync runs.
- [ ] Local dry-run test confirms `cli enrich` exits with code 0.

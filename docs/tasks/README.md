# MCP Vulnerability Advisory Database — Task Board Roadmap

Private GitHub Project Board: [https://github.com/users/JMartynov/projects/4](https://github.com/users/JMartynov/projects/4)

---

## Task Catalog & Implementation Status

### 1. Foundational Ingestion & Empirical Audit Tracks (100% Tested & Merged)

| # | Task | Subsystem | Status | Key Deliverable & Verification | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **00-A** | **GHSA Cursor Pagination & Commit Delta Traversal** | Live Stream Ingestion | `Done` | RFC 5988 `Link` pagination & commit delta markers in `pipeline.py`; 100% acceptance tests passed. | [task00a_ghsa_cursor_pagination.md](../../.jules/task00a_ghsa_cursor_pagination.md) |
| **00-B** | **PyPI Lazy Version Resolution & Cache Invalidation** | Package Discovery | `Done` | PEP 691 JSON resolution & TTL invalidation in `pypi.py` & `catalog_state.py`; unit tests passed. | [task00b_pypi_lazy_version_resolution.md](../../.jules/task00b_pypi_lazy_version_resolution.md) |
| **00-C** | **Historical Advisory Pre-Loading & Index Preservation** | Search Index Engine | `Done` | `_load_existing_records()` enforcing monotonic non-destructive indexing; incremental tests passed. | [task00c_index_preservation.md](../../.jules/task00c_index_preservation.md) |
| **00-D** | **OSV 1.6 Range Integrity & Deduplicator Event Grouping** | Data Normalization | `Done` | Deduplicator grouping by `(type, repo)` with valid `introduced`/`fixed` pairs; schema tests passed. | [task00d_range_integrity_event_grouping.md](../../.jules/task00d_range_integrity_event_grouping.md) |
| **00-E** | **400-URL Empirical Data Integrity Master Audit** | Empirical Verification | `Done` | Complete audit across 400 real upstream endpoints documented in `docs/reports/PARALLEL_AUDIT_REPORT.md`. | [task00e_400_url_empirical_audit.md](../../.jules/task00e_400_url_empirical_audit.md) |

---

### 2. Core Enhancements & Release Engineering (100% Tested & Merged)

| # | Task | Subsystem | Status | Key Deliverable & Verification | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **01** | **GitHub API Token & Rate-Limit Protection** | Ingestion Stream | `Done` | `_get_github_headers()` with `GITHUB_TOKEN`/`GH_TOKEN` support for 5,000 req/hr quota; unit tests passed. | [task01_github_token_rate_limit.md](../../.jules/task01_github_token_rate_limit.md) |
| **02** | **Pull Request Continuous Integration (ci.yml)** | Automated CI Gates | `Done` | `.github/workflows/ci.yml` gating PRs with schema validation and test suites across Python 3.12 and 3.14. | [task02_pr_ci_workflow.md](../../.jules/task02_pr_ci_workflow.md) |
| **03** | **Async Catalog Version Enricher** | Discovery Engine | `Done` | `CatalogVersionEnricher` (`discovery/enricher.py`) and CLI subcommand `enrich` with threadpool workers. | [task03_async_catalog_enricher.md](../../.jules/task03_async_catalog_enricher.md) |
| **04** | **OSV Batch Version Stamping (currently_vulnerable)** | Search Index | `Done` | Version payload in OSV queries + `is_version_affected()` evaluator stamping `currently_vulnerable` in `index.json`. | [task04_osv_version_stamping.md](../../.jules/task04_osv_version_stamping.md) |
| **05** | **Modern Lockfile Auditing (uv.lock, pyproject.toml)** | Transitive Scanner | `Done` | Built-in `tomllib` parsers for `uv.lock`, PEP 621 `pyproject.toml`, and Poetry lockfiles in `transitive.py`. | [task05_modern_lockfile_auditing.md](../../.jules/task05_modern_lockfile_auditing.md) |
| **06** | **Web Explorer UI Enhancements (OSV 1.6 Extensions)** | Static Web Dashboard | `Done` | DOM chips for vulnerable tools, OWASP MCP Top 10 badges, and remediation callouts in `docs/app.js` and `docs/style.css`. | [task06_web_explorer_ui_enhancements.md](../../.jules/task06_web_explorer_ui_enhancements.md) |
| **07** | **PyPI Trusted Publishing (release.yml & v1.0.0 Tagging)** | Release Automation | `Done` | `.github/workflows/release.yml` with OIDC Trusted Publishing, `pypi` environment, and README documentation for v1.0.0 tagging. | [task07_pypi_trusted_publishing.md](../../.jules/task07_pypi_trusted_publishing.md) |

---

### 3. Active Roadmap Implementation Tasks on the Board

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **08** | **Automated Catalog Enrichment Cron in CI** | Daily Sync Automation | `Todo` | Automatically runs `cli enrich --limit 500` in `.github/workflows/daily_sync.yml` nightly. | [task08_daily_sync_enrich_cron.md](../../.jules/task08_daily_sync_enrich_cron.md) |
| **09** | **AI Client Config Auto-Fixer (cli fix-config)** | Client Security CLI | `Todo` | Automated remediation command rewriting vulnerable MCP servers in `claude_desktop_config.json`. | [task09_client_config_autofixer.md](../../.jules/task09_client_config_autofixer.md) |
| **10** | **Real-Time Threat Feed Webhook Dispatcher** | Threat Intelligence | `Todo` | Pushes real-time alerts to Discord, Slack, and GitHub Discussions on newly detected CRITICAL/HIGH advisories. | [task10_threat_feed_webhook_notifier.md](../../.jules/task10_threat_feed_webhook_notifier.md) |
| **11** | **Offline Air-Gapped Enterprise Export Bundle** | Enterprise Distribution | `Todo` | Packages standalone tarball (`mcp-offline.tar.gz`) with embedded zero-dependency query script. | [task11_airgap_export_bundle.md](../../.jules/task11_airgap_export_bundle.md) |
| **12** | **OWASP MCP Top 10 & CWE Analytics Dashboard** | Static Web Explorer | `Todo` | Generates visual distribution charts for top vulnerable tools and OWASP categories in `docs/analytics.html`. | [task12_owasp_analytics_dashboard.md](../../.jules/task12_owasp_analytics_dashboard.md) |
| **13** | **Official Lightweight Docker Image & GHCR Publish** | Containerization & DevSecOps | `Todo` | Multi-arch `Dockerfile` and automated publishing workflow to `ghcr.io/jmartynov/mcp-vulnerabilities`. | [task13_docker_ghcr_container.md](../../.jules/task13_docker_ghcr_container.md) |
| **14** | **Direct Vulnerability Search & Inspection CLI** | Terminal Developer Experience | `Todo` | Subcommands `mcp-vuln search` and `lookup` for querying by CVE/GHSA ID, tool name, or ecosystem. | [task14_cli_search_lookup.md](../../.jules/task14_cli_search_lookup.md) |
| **15** | **Reusable GitHub Action for CI/CD Scanning** | DevSecOps Integration | `Todo` | Root `action.yml` enabling 4-line turn-key MCP vulnerability scanning across pull requests. | [task15_github_action_ci.md](../../.jules/task15_github_action_ci.md) |
| **16** | **Upstream OSV.dev Exporter & Ecosystem Pipeline** | Global Security Data Lake | `Todo` | Automated export pipeline (`all.zip` and manifest) for upstream inclusion in Google OSV.dev. | [task16_osv_export_pipeline.md](../../.jules/task16_osv_export_pipeline.md) |

---

## Verification Test Results
```
.venv/bin/pytest
============================= 84 passed in 10.66s ==============================
```
- Total test count: **84**
- Passing: **84 (100%)**
- Skipped / Failed: **0**

# MCP Vulnerability Advisory Database — Next Tasks Roadmap

This directory contains detailed, contract-first task descriptions ready for delegation via **Google Jules (EULIS)** or automated agent orchestration.

---

## Task Catalog

| # | Task | Subsystem | Target Files | Contract File |
| :---: | :--- | :--- | :--- | :--- |
| **01** | **GitHub API Token & Rate-Limit Protection** | Upstream Ingestion Feeds | `src/mcp_vulnerabilities/pipeline.py`, `.github/workflows/daily_sync.yml` | [task01_github_token_rate_limit.md](../../.jules/task01_github_token_rate_limit.md) |
| **02** | **Pull Request Continuous Integration Workflow** | Automated CI Gates | `.github/workflows/ci.yml` | [task02_pr_ci_workflow.md](../../.jules/task02_pr_ci_workflow.md) |
| **03** | **Asynchronous Catalog Version Enrichment Engine** | Discovery & Maintenance | `src/mcp_vulnerabilities/discovery/enricher.py`, `src/mcp_vulnerabilities/cli.py` | [task03_async_catalog_enricher.md](../../.jules/task03_async_catalog_enricher.md) |
| **04** | **OSV Batch Version Stamping (`currently_vulnerable`)** | Ingestion & Index | `src/mcp_vulnerabilities/pipeline.py`, `data/vulnerabilities/index.json` | [task04_osv_version_stamping.md](../../.jules/task04_osv_version_stamping.md) |
| **05** | **Modern Python Lockfile Auditing (`uv.lock`, `pyproject.toml`)** | Transitive Scanner | `src/mcp_vulnerabilities/transitive.py`, `src/mcp_vulnerabilities/cli.py` | [task05_modern_lockfile_auditing.md](../../.jules/task05_modern_lockfile_auditing.md) |
| **06** | **Web Explorer UI Enhancement for OSV 1.6 Extensions** | Static Web Dashboard | `docs/app.js`, `docs/index.html`, `src/mcp_vulnerabilities/site_builder.py` | [task06_web_explorer_ui_enhancements.md](../../.jules/task06_web_explorer_ui_enhancements.md) |

---

## Delegation Command Reference
To launch any of these tasks in Google Jules:
```bash
jules new --repo "JMartynov/mcp-vulnerabilities" < .jules/task01_github_token_rate_limit.md
```
Or dispatch all 6 tasks in parallel using the `jules-task-controller` skill:
```bash
jules-gate wait $S1 $S2 $S3 $S4 $S5 $S6 --timeout 30
```

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

### 3. Advanced Integrations & Ecosystem Pipelines (100% Tested & Merged)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **08** | **Automated Catalog Enrichment Cron in CI** | Daily Sync Automation | `Done` | Automatically runs `cli enrich --limit 500` in `.github/workflows/daily_sync.yml` nightly. | [task08_daily_sync_enrich_cron.md](../../.jules/task08_daily_sync_enrich_cron.md) |
| **09** | **AI Client Config Auto-Fixer (cli fix-config)** | Client Security CLI | `Done` | Automated remediation command rewriting vulnerable MCP servers in `claude_desktop_config.json`. | [task09_client_config_autofixer.md](../../.jules/task09_client_config_autofixer.md) |
| **10** | **Real-Time Threat Feed Webhook Dispatcher** | Threat Intelligence | `Done` | Pushes real-time alerts to Discord, Slack, and GitHub Discussions on newly detected CRITICAL/HIGH advisories. | [task10_threat_feed_webhook_notifier.md](../../.jules/task10_threat_feed_webhook_notifier.md) |
| **11** | **Offline Air-Gapped Enterprise Export Bundle** | Enterprise Distribution | `Done` | Packages standalone tarball (`mcp-offline.tar.gz`) with embedded zero-dependency query script. | [task11_airgap_export_bundle.md](../../.jules/task11_airgap_export_bundle.md) |
| **12** | **OWASP MCP Top 10 & CWE Analytics Dashboard** | Static Web Explorer | `Done` | Generates visual distribution charts for top vulnerable tools and OWASP categories in `docs/analytics.html`. | [task12_owasp_analytics_dashboard.md](../../.jules/task12_owasp_analytics_dashboard.md) |
| **13** | **Official Lightweight Docker Image & GHCR Publish** | Containerization & DevSecOps | `Done` | Multi-arch `Dockerfile` and automated publishing workflow to `ghcr.io/jmartynov/mcp-vulnerabilities`. | [task13_docker_ghcr_container.md](../../.jules/task13_docker_ghcr_container.md) |
| **14** | **Direct Vulnerability Search & Inspection CLI** | Terminal Developer Experience | `Done` | Subcommands `mcp-vuln search` and `lookup` for querying by CVE/GHSA ID, tool name, or ecosystem. | [task14_cli_search_lookup.md](../../.jules/task14_cli_search_lookup.md) |
| **15** | **Reusable GitHub Action for CI/CD Scanning** | DevSecOps Integration | `Done` | Root `action.yml` enabling 4-line turn-key MCP vulnerability scanning across pull requests. | [task15_github_action_ci.md](../../.jules/task15_github_action_ci.md) |
| **16** | **Upstream OSV.dev Exporter & Ecosystem Pipeline** | Global Security Data Lake | `Done` | Automated export pipeline (`all.zip` and manifest) for upstream inclusion in Google OSV.dev. | [task16_osv_export_pipeline.md](../../.jules/task16_osv_export_pipeline.md) |

---

### 4. Enterprise Standards & Runtime Security Wave (100% Tested & Merged)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **17** | **SARIF Export for GitHub Code Scanning (--format sarif)** | Enterprise DevSecOps | `Done` | Emits OASIS SARIF v2.1.0 for native PR annotations in GitHub Code Scanning. | [task17_sarif_export.md](../../.jules/task17_sarif_export.md) |
| **18** | **Live MCP Protocol Probe & Tool Auditor (cli probe)** | Runtime Protocol Security | `Done` | Connects via stdio/SSE, performs JSON-RPC handshake, and fingerprints live tools against CVEs. | [task18_live_mcp_probe.md](../../.jules/task18_live_mcp_probe.md) |

---

### 5. Threat Intelligence & Distribution Automation Wave (100% Tested & Merged)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **20** | **NVD 2.0 API Ingestion Stream & Converter Pipeline** | Threat Intelligence | `Done` | Connects NIST NVD 2.0 REST API with rate-limiting and MCP relevance filtering. | [task20_nvd_api_stream.md](../../.jules/task20_nvd_api_stream.md) |
| **21** | **Automated Periodic Snapshot Distribution (snapshot_release.yml)** | Automated Releases | `Done` | Bi-weekly GitHub Action compiling and releasing snapshot archives with SHA-256 sums. | [task21_snapshot_release_automation.md](../../.jules/task21_snapshot_release_automation.md) |

---

### 6. Advanced Threat Engines & Enterprise Architecture Wave (Active Wave)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **22** | **MCP Fingerprints Integration & Server Identification** | AST & Signature Engine | `Done` | Integrates 5,033+ server passports (`passports.json.gz`), canonical tool hashing, unlabelled server identification, and multi-server tool collision/shadowing detection. | [task22_fingerprint_server_identification.md](../../.jules/task22_fingerprint_server_identification.md) |
| **23** | **Multi-Engine Heuristic Threat Analyzer (YARA & RegEx)** | Threat Detection Engines | `Done` | High-performance rule-based threat engine detecting Prompt Injection, Arbitrary Code Execution, and Credential Exfiltration with zero cloud dependencies. | [task23_heuristic_threat_analyzers.md](../../.jules/task23_heuristic_threat_analyzers.md) |
| **24** | **Headless REST API Gateway & Microservice Daemon (`mcp-vuln serve`)** | Enterprise Microservice | `Done` | Lightweight HTTP REST daemon exposing endpoints for live probing, server identification, configuration auditing, and OSV querying with OpenAPI 3.0 specs. | [task24_rest_api_server_daemon.md](../../.jules/task24_rest_api_server_daemon.md) |
| **25** | **Full-Surface Protocol Probe & Live SSE / Streamable HTTP** | Runtime Protocol Security | `Done` | Implements bidirectional SSE and Streamable HTTP transports with authentication headers, probing tools, prompts, resources, and server instructions. | [task25_full_surface_protocol_probe_sse.md](../../.jules/task25_full_surface_protocol_probe_sse.md) |
| **26** | **MCP Production Readiness & Schema Contract Linter** | Contract Hygiene & Linting | `Done` | Zero-dependency static schema analyzer enforcing parameter typing, description hygiene, required field definitions, and error handling contracts. | [task26_production_readiness_schema_linter.md](../../.jules/task26_production_readiness_schema_linter.md) |
| **27** | **Isolated Ephemeral Container Sandbox (PyPI & npm)** | Dynamic Sandboxed Auditing | `Done` | Safe, unprivileged Docker/Podman container execution to download, install, and capture live runtime tools from untrusted packages without host risk. | [task27_container_sandbox_package_auditor.md](../../.jules/task27_container_sandbox_package_auditor.md) |
| **28** | **Static AST Source Code Taint & Dangerous Sink Analyzer** | Static Application Security (SAST) | `Done` | Native AST dataflow engine tracing MCP tool parameters into dangerous execution sinks (`subprocess`, `eval`, path traversal, SQL injection) in local repos. | [task28_static_ast_taint_sink_analyzer.md](../../.jules/task28_static_ast_taint_sink_analyzer.md) |
| **29** | **Binary Asset & File Hash Malware Screening** | Threat Intelligence & Malware | `Done` | Streaming 64 KB SHA-256 cryptographic hasher screening bundled binaries and archives against an offline blocklist with optional passive VirusTotal queries. | [task29_binary_asset_malware_screening.md](../../.jules/task29_binary_asset_malware_screening.md) |

---

### 7. Core Hardening, Sandboxing & Enterprise Compliance Wave (Wave 7 - 100% Tested & Merged)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **30** | **Subprocess Stderr Deadlock Elimination & API Daemon Transport Signature Hardening** | Runtime Stdio & API Hardening | `Done` | Eliminates OS pipe buffer deadlocks with background stderr drain threads, ring buffers, and hardens API daemon command signature arguments against RCE. | [task30_transport_deadlock_and_api_signature_hardening.md](../../.jules/task30_transport_deadlock_and_api_signature_hardening.md) |
| **31** | **Two-Stage Airgapped Container Sandbox Isolation** | Dynamic Sandboxed Auditing | `Done` | Two-phase isolated sandboxing separating network fetch from an airgapped execution container (`--network none`, `--read-only`, `--cap-drop ALL`, CPU/memory quotas). | [task31_airgapped_sandbox_two_stage_isolation.md](../../.jules/task31_airgapped_sandbox_two_stage_isolation.md) |
| **32** | **OWASP MCP Top 10:2025 Automated Compliance Scorer & SARIF Tagger** | Compliance & Auditing | `Done` | Maps threat findings, readiness issues, and AST taint sinks to OWASP Top 10:2025 and OWASP MCP frameworks with CLI scoring and SARIF tagging. | [task32_owasp_mcp_top10_compliance_scorer.md](../../.jules/task32_owasp_mcp_top10_compliance_scorer.md) |
| **33** | **CycloneDX 1.6 & SPDX 3.0 AI-BOM Exporter** | Software Supply Chain (SBOM) | `Done` | Generates standard CycloneDX 1.6 SBOMs capturing MCP servers, canonical tools hashes, endpoints, and VEX vulnerability representations. | [task33_cyclonedx_aibom_exporter.md](../../.jules/task33_cyclonedx_aibom_exporter.md) |
| **34** | **AST Taint Sanitizer Registry & Inter-Procedural Propagation** | Static Application Security (SAST) | `Done` | Extends AST taint analyzer with customizable sanitizer registry, inter-procedural helper propagation, and sink category-specific neutralization. | [task34_ast_taint_sanitizer_registry.md](../../.jules/task34_ast_taint_sanitizer_registry.md) |

---

---

### 8. Architectural Unification, Versioning & Ecosystem Security Wave (Wave 8 - Active Wave)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **35** | **Capability Risk Classifier & Human-Readable Security Commentary Engine** | Threat Analysis & Risk Engine | `Done` | Implement a specialized `CapabilityRiskClassifier` and `SecurityCommentaryEngine` in `src/mcp_vulnerabilities/analyzers/` (migrating and ele... | [task35_capability_risk_classifier.md](../../.jules/task35_capability_risk_classifier.md) |
| **36** | **Multi-Server Conflict Detector, Automated Resolver, SARIF Collision Rules & Config Exporters Migration** | Client Security & Configuration | `Done` | Migrate, integrate, and extend the multi-server conflict detector (`conflict_detector.py`), automated config resolver (`conflict_resolver.py... | [task36_conflict_detector_resolver_migration.md](../../.jules/task36_conflict_detector_resolver_migration.md) |
| **37** | **Unified Container/VM Sandbox Drivers, Pre-Commit Security Hooks & API Route Bugfix** | Runtime Sandbox & API Daemon | `Done` | Consolidate container and VM sandbox execution drivers (`DockerSandboxRunner`, `IncusSandboxRunner`, fallback `HostRunner`) within `src/mcp_... | [task37_unified_sandbox_drivers_precommit_hooks.md](../../.jules/task37_unified_sandbox_drivers_precommit_hooks.md) |
| **38** | **Version-Separated Vulnerability & Passport Correlation Engine + CLI Expansion** | Vulnerability Correlation & Indexing | `Todo` | Implement a version-separated vulnerability and passport correlation engine (`src/mcp_vulnerabilities/fingerprints/correlator.py`) that inde... | [task38_version_separated_correlation_engine.md](../../.jules/task38_version_separated_correlation_engine.md) |
| **39** | **Version-Aware Unified Site Builder & Sharded Server Datasets** | Static Site Generator & Sharding | `Todo` | Refactor `src/mcp_vulnerabilities/site_builder.py` into a high-performance static site generator that produces version-aware security datase... | [task39_version_aware_site_builder_sharded_data.md](../../.jules/task39_version_aware_site_builder_sharded_data.md) |
| **40** | **Unified Security, Version Vulnerability Timeline & Fingerprint Web Portal UI** | Web Security Portal | `Todo` | Redesign and enhance the web portal (`docs/index.html`, `docs/app.js`, `docs/style.css`, `docs/timeline.js`) into a unified security and fin... | [task40_web_portal_timeline_ui.md](../../.jules/task40_web_portal_timeline_ui.md) |
| **41** | **Cross-Repo Snapshot Sync, Daily Workflow Alignment & Final E2E Verification** | Cross-Repo Automation & CI | `Todo` | Establish automated cross-repository snapshot synchronization and daily workflow alignment between `mcp-fingerprints` and `mcp-vulnerabiliti... | [task41_cross_repo_snapshot_sync.md](../../.jules/task41_cross_repo_snapshot_sync.md) |
| **42** | **Automated Sync Delta Detection, Version Bumper (bump_version.py) & PyPI Release Pipeline** | Release Engineering & Automation | `Todo` | Implement automated sync delta detection (`src/mcp_vulnerabilities/delta_detector.py`) to identify substantive security data updates (new CV... | [task42_delta_detection_version_bumper_release.md](../../.jules/task42_delta_detection_version_bumper_release.md) |
| **43** | **Per-Update Release Delta Feed & Dedicated Updates Web Page (docs/updates.html)** | Threat Intelligence Feed & UI | `Todo` | Generate a per-update release delta feed (`docs/feed.json`, `docs/feed.xml`) and build a dedicated 'Updates & Threat Advisories' web page (`... | [task43_release_delta_feed_updates_page.md](../../.jules/task43_release_delta_feed_updates_page.md) |

## Verification Test Results
```
.venv/bin/pytest
============================= 247 passed in 41.34s =============================
```
- Total test count: **247**
- Passing: **247 (100%)**
- Skipped / Failed: **0**




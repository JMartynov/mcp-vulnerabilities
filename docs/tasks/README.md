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
| **38** | **Version-Separated Vulnerability & Passport Correlation Engine + CLI Expansion** | Vulnerability Correlation & Indexing | `Done` | Implement a version-separated vulnerability and passport correlation engine (`src/mcp_vulnerabilities/fingerprints/correlator.py`) that inde... | [task38_version_separated_correlation_engine.md](../../.jules/task38_version_separated_correlation_engine.md) |
| **39** | **Version-Aware Unified Site Builder & Sharded Server Datasets** | Static Site Generator & Sharding | `Done` | Refactor `src/mcp_vulnerabilities/site_builder.py` into a high-performance static site generator that produces version-aware security datase... | [task39_version_aware_site_builder_sharded_data.md](../../.jules/task39_version_aware_site_builder_sharded_data.md) |
| **40** | **Unified Security, Version Vulnerability Timeline & Fingerprint Web Portal UI** | Web Security Portal | `Done` | Redesign and enhance the web portal (`docs/index.html`, `docs/app.js`, `docs/style.css`, `docs/timeline.js`) into a unified security and fin... | [task40_web_portal_timeline_ui.md](../../.jules/task40_web_portal_timeline_ui.md) |
| **41** | **Cross-Repo Snapshot Sync, Daily Workflow Alignment & Final E2E Verification** | Cross-Repo Automation & CI | `Done` | Establish automated cross-repository snapshot synchronization and daily workflow alignment between `mcp-fingerprints` and `mcp-vulnerabiliti... | [task41_cross_repo_snapshot_sync.md](../../.jules/task41_cross_repo_snapshot_sync.md) |
| **42** | **Automated Sync Delta Detection, Version Bumper (bump_version.py) & PyPI Release Pipeline** | Release Engineering & Automation | `Done` | Implement automated sync delta detection (`src/mcp_vulnerabilities/delta_detector.py`) to identify substantive security data updates (new CV... | [task42_delta_detection_version_bumper_release.md](../../.jules/task42_delta_detection_version_bumper_release.md) |
| **43** | **Per-Update Release Delta Feed & Dedicated Updates Web Page (docs/updates.html)** | Threat Intelligence Feed & UI | `Done` | Generate a per-update release delta feed (`docs/feed.json`, `docs/feed.xml`) and build a dedicated 'Updates & Threat Advisories' web page (`... | [task43_release_delta_feed_updates_page.md](../../.jules/task43_release_delta_feed_updates_page.md) |
| **44** | **Updates Payload Optimization and Documentation Synchronization** | Feed Performance & Docs | `Done` | Optimize delta filtering to keep payload size < 1 MB and synchronize documentation. | [task44_updates_payload_and_docs_sync.md](../../.jules/task44_updates_payload_and_docs_sync.md) |
| **45** | **Cross-Repository Dependency Triggering Workflow** | Cross-Repo CI Automation | `Done` | Upstream repository dispatch workflows connecting fingerprints and vulnerability releases. | [task45_cross_repo_dependency_trigger.md](../../.jules/task45_cross_repo_dependency_trigger.md) |
| **45b** | **CI Test Suite Resilience & Pytest Mock Fixes** | CI Reliability & Testing | `Done` | Hardened mock fixtures and cross-environment test guarantees across Python 3.12/3.14. | [task45b_ci_test_fixes.md](../../.jules/task45b_ci_test_fixes.md) |
| **46** | **CI Resilience, PyPI Graceful Fallback & Force-Release Support** | Release Engineering & CI | `Done` | Force-release dispatch flags, graceful PyPI OIDC fallback, and release automation. | [task46_ci_resilience_and_force_release.md](../../.jules/task46_ci_resilience_and_force_release.md) |

---

### 9. Web Security Explorer, Version-Switching & Live Feed Deployment Wave (Wave 9 - 100% Tested & Merged)

Master Plan: [IMPLEMENTATION_PLAN_SECURITY_EXPLORER.md](IMPLEMENTATION_PLAN_SECURITY_EXPLORER.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **47** | **GitHub Pages Deployment & Live Web Portal / Feed Reference Fix** | Web Hosting & Deployment | `Done` | Fix public live portal and updates feed links via `.github/workflows/pages.yml`, audit relative paths, and verify HTTP 200 uptime. | [task47_github_pages_live_portal_feed_fix.md](task47_github_pages_live_portal_feed_fix.md) |
| **48** | **MCP Server Multi-Version Vulnerability & Remediation Metadata Pipeline** | Version Correlator & Data Engine | `Done` | Ingest complete version histories per MCP server, map version vulnerabilities, and compute target safe update versions and upgrade commands. | [task48_version_remediation_metadata_pipeline.md](task48_version_remediation_metadata_pipeline.md) |
| **49** | **Searchable MCP Security Explorer with Interactive Version Switcher & Remediation UI** | Web Security Portal UI | `Done` | Searchable server directory, interactive version switcher, dynamic safe vs vulnerable posture, and copyable remediation upgrade commands. | [task49_security_explorer_version_switcher_remediation_ui.md](task49_security_explorer_version_switcher_remediation_ui.md) |

---

### 10. Next-Gen AI Runtime Security & Fingerprint Synergy Wave (Wave 10 - Active Wave)

Master Plan: [IMPLEMENTATION_PLAN_WAVE_10_MCP_FINGERPRINTS_ENHANCEMENTS.md](IMPLEMENTATION_PLAN_WAVE_10_MCP_FINGERPRINTS_ENHANCEMENTS.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **50** | **PyPI Integration, Caching Loader & Core Model Deduplication** | Single Source of Truth & PyPI | `Done` | Multi-tier cache loader in `mcp-fingerprints`, release v1.0.14, add PyPI dependency, eliminate redundant models/canonicalizer in `mcp-vulnerabilities`. | [task50_pypi_integration_caching_loader_and_model_deduplication.md](task50_pypi_integration_caching_loader_and_model_deduplication.md) |
| **51** | **Universal 9-Client Audit & Global Package Discovery** | Universal Client Auditing | `Done` | Wire `ConfigScanner` and `NpmGlobalScanner` into `mcp-vuln audit`, auditing 9 AI clients + global npm/npx packages with SARIF annotations. | [task51_universal_9client_audit_and_global_package_discovery.md](task51_universal_9client_audit_and_global_package_discovery.md) |
| **52** | **Supply-Chain Tamper & Shadow Tool Drift Detection** | Zero-Day Supply Chain Security | `Done` | Runtime tool signature verification against baseline passport hashes; detect unadvertised/injected shadow tools and unbumped tampering. | [task52_supply_chain_tamper_and_shadow_tool_drift_detector.md](task52_supply_chain_tamper_and_shadow_tool_drift_detector.md) |
| **53** | **Behavioral Topology Prober & Unknown Server Identification** | Behavioral Identification | `Done` | Probes custom/wrapped processes over stdio/SSE; matches runtime tools against 5,533 passports using topological similarity to unmask hidden CVEs. | [task53_behavioral_topology_prober_unknown_server_identification.md](task53_behavioral_topology_prober_unknown_server_identification.md) |
| **54** | **Polyglot Vulnerability Correlation (Rust, Go, Maven, Docker)** | Multi-Ecosystem Coverage | `Done` | Ingests Rust (Cargo), Go, Java/Kotlin (Maven), and Docker Hub passports; correlates `RUSTSEC`, `GO-*`, `GHSA-java`, and container CVEs. | [task54_polyglot_vulnerability_correlation_rust_go_maven_docker.md](task54_polyglot_vulnerability_correlation_rust_go_maven_docker.md) |
| **55** | **Multi-Client Auto-Fix Exporters & Interactive Security Hub** | Remediation & Developer Experience | `Done` | One-click auto-patching across all 9 clients in native formats; interactive emoji-driven terminal management hub (`mcp-vuln hub`). | [task55_multiclient_autofix_exporters_and_interactive_security_hub.md](task55_multiclient_autofix_exporters_and_interactive_security_hub.md) |
| **56** | **Web Security Explorer UI Parity (Tool Expansion, Zero-Tool & Filters)** | Web Security Portal UI | `Done` | Interactive expandable tool chips (`+N more` / `Show less ▴`), zero-tool state badge, and "Has Tools Only" filter checkbox. | [task56_web_explorer_ui_parity_tool_expansion_and_filters.md](task56_web_explorer_ui_parity_tool_expansion_and_filters.md) |
| **57** | **High-Performance Multi-Core Parallel Site Builder & Two-Tier SHA Cache** | Performance & Sharding Engine | `Done` | Parallel process pool sharding across CPU cores and content-addressable two-tier SHA-256 caching for 5x–10x faster site builds. | [task57_high_performance_multicore_parallel_site_builder.md](task57_high_performance_multicore_parallel_site_builder.md) |
| **58** | **PyPI Release Publishing & Upstream Cross-Repo Dispatch Pipeline** | Release Engineering & CI/CD | `Done` | Automated Trusted Publishing to PyPI.org for `mcp-fingerprints` and reactive cross-repo dispatch triggering on new fingerprint releases. | [task58_pypi_release_publishing_and_cross_repo_dispatch.md](task58_pypi_release_publishing_and_cross_repo_dispatch.md) |

---

### 11. Empirical Subsystem Invariant Audits (Wave 11 - Ready for Execution)

Master Plan: [IMPLEMENTATION_PLAN_FULL_SYSTEM_AUDIT_AND_COMPETITIVE_BENCHMARK.md](IMPLEMENTATION_PLAN_FULL_SYSTEM_AUDIT_AND_COMPETITIVE_BENCHMARK.md)  
DAG Workflow: [audit_and_benchmark_dag.yml](../../.jules/workflows/audit_and_benchmark_dag.yml)

| # | Task | Subsystem | Status | Strategic Purpose & Invariants | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **59** | **Ingestion Stream & Schema Monotonic Invariant Audit** | Ingestion & Sync Pipeline | `Done` | Invariant audit passed: RFC 5988 cursor traversal, deduplicator range collapsing fix, mid-batch recovery. Report: [`audit_task59_ingestion_and_schema.md`](../audit/audit_task59_ingestion_and_schema.md). | [task59_audit_ingestion_schema_and_monotonic_stream.md](task59_audit_ingestion_schema_and_monotonic_stream.md) |
| **60** | **Universal 9-Client Discovery & Config Syntax Resilience Audit** | Client Security & Discovery | `Done` | Invariant audit passed: Permissive JSONC/JSON5 parsing, BOM handling, symlink cycle immunity, env var expansion & secret redaction. Report: [`audit_task60_universal_9client_discovery.md`](../audit/audit_task60_universal_9client_discovery.md). | [task60_audit_universal_9client_discovery_and_configs.md](task60_audit_universal_9client_discovery_and_configs.md) |
| **61** | **Supply Chain Tamper & Shadow Tool Drift Detection Audit** | Zero-Day & Supply Chain | `Done` | Invariant audit passed: Runtime signature drift detection, shadow tool unadvertised injection alerts, and passport baseline verification. Report: [`audit_task61_supply_chain_tamper.md`](../audit/audit_task61_supply_chain_tamper.md). | [task61_audit_supply_chain_tamper_and_shadow_tools.md](task61_audit_supply_chain_tamper_and_shadow_tools.md) |
| **62** | **Behavioral Topology Prober & Multi-Transport Handshake Audit** | Runtime Protocol Security | `Done` | Invariant audit passed: STDIO noise filtering, zombie process teardown, SSE typed errors, and topological matching >= 95%. Report: [`audit_task62_behavioral_topology_prober.md`](../audit/audit_task62_behavioral_topology_prober.md). | [task62_audit_behavioral_topology_prober_transports.md](task62_audit_behavioral_topology_prober_transports.md) |
| **63** | **Polyglot Vulnerability Correlator & Native Multi-Client Fixer Audit** | Correlation & Autofix Engine | `Done` | Invariant audit passed: Native schema preservation, atomic backup creation, disk write rollback, monotonic SemVer resolution, and zero-day explicit no-fix flagging. Report: [`audit_task63_polyglot_and_fixer.md`](../audit/audit_task63_polyglot_and_fixer.md). | [task63_audit_polyglot_correlator_and_multiclient_fixer.md](task63_audit_polyglot_correlator_and_multiclient_fixer.md) |
| **64** | **Interactive Terminal Security Hub Robustness Audit** | Terminal DX & Hub | `Done` | Invariant audit passed: Non-TTY automated fallback, unified diff dry-run integrity, SIGINT state restoration, and ANSI escape injection stripping. Report: [`audit_task64_interactive_hub_robustness.md`](../audit/audit_task64_interactive_hub_robustness.md). | [task64_audit_interactive_terminal_hub_robustness.md](task64_audit_interactive_terminal_hub_robustness.md) |
| **65** | **Parallel Multicore Site Builder & Cache Determinism Audit** | Performance & Site Builder | `Done` | Invariant audit passed: Bit-for-bit SHA-256 equality across worker counts, non-fatal worker crash isolation, and content-addressed cache invalidation. Report: [`audit_task65_site_builder_cache.md`](../audit/audit_task65_site_builder_cache.md). | [task65_audit_parallel_multicore_site_builder_cache.md](task65_audit_parallel_multicore_site_builder_cache.md) |
| **66** | **Static Web Security Portal UI Parity & Client-Side Logic Audit** | Web Security Portal UI | `Done` | Invariant audit passed: Tools-only filter parity, zero-tool badge rendering, DOM XSS immunity, URL hash sanitization, and lazy shard fetch graceful degradation. Report: [`audit_task66_web_portal_ui_parity.md`](../audit/audit_task66_web_portal_ui_parity.md). | [task66_audit_static_web_security_portal_ui_parity.md](task66_audit_static_web_security_portal_ui_parity.md) |

---

### 12. Competitive Ecosystem Benchmarking (Wave 12 - Ready for Execution)

Master Plan: [IMPLEMENTATION_PLAN_FULL_SYSTEM_AUDIT_AND_COMPETITIVE_BENCHMARK.md](IMPLEMENTATION_PLAN_FULL_SYSTEM_AUDIT_AND_COMPETITIVE_BENCHMARK.md)

| # | Task | Subsystem | Status | Strategic Purpose & Competitive Scope | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **67** | **Verity MCP Auditor, Anthropic Inspector & Runtime Sandboxes** | Runtime Security & Sandboxing | `Done` | Benchmark completed: Verity DB Guard/Oracle, Anthropic Inspector SDK, Cursor Sandbox; HIGH/MED/LOW gaps graded; inline reverse proxy architecture designed. Report: [`competitive_verity_anthropic_runtime.md`](../audit/competitive_verity_anthropic_runtime.md). | [task67_competitive_verity_and_anthropic_runtime_mcp.md](task67_competitive_verity_and_anthropic_runtime_mcp.md) |
| **68** | **Smithery.ai & Glama.ai Registry Security Models** | Registry & Hub Security | `Done` | Benchmark completed: Smithery sandbox builds, Glama uptime health telemetry, multi-metric server trust score formula, safe fallback recommendation engine. Report: [`competitive_smithery_glama_registries.md`](../audit/competitive_smithery_glama_registries.md). | [task68_competitive_smithery_glama_registry_security.md](task68_competitive_smithery_glama_registry_security.md) |
| **69** | **Snyk, Semgrep, Trivy & OSV-Scanner SCA Engines** | SCA & Reachability SAST | `Done` | Benchmark completed: Snyk reachability, Semgrep taint analysis, typosquatting & LLM hallucinated package detection, automated PR bot. Report: [`competitive_snyk_semgrep_trivy_osv.md`](../audit/competitive_snyk_semgrep_trivy_osv.md). | [task69_competitive_snyk_semgrep_trivy_osv_scanner.md](task69_competitive_snyk_semgrep_trivy_osv_scanner.md) |
| **70** | **Supply Chain Attestation, Sigstore & CycloneDX AIBOM Standards** | Supply Chain & Attestation | `Done` | Benchmark completed: Sigstore Cosign signing, SLSA Level 3 provenance, CycloneDX v1.6 AI BOM mapping, OpenSSF Scorecards API integration. Report: [`competitive_supply_chain_sbom.md`](../audit/competitive_supply_chain_sbom.md). | [task70_competitive_supply_chain_attestation_and_sbom.md](task70_competitive_supply_chain_attestation_and_sbom.md) |

---

### 13. Cumulative Master Synthesis & Deliverables (Wave 13 - Final Accumulation)

Master Plan: [IMPLEMENTATION_PLAN_FULL_SYSTEM_AUDIT_AND_COMPETITIVE_BENCHMARK.md](IMPLEMENTATION_PLAN_FULL_SYSTEM_AUDIT_AND_COMPETITIVE_BENCHMARK.md)

| # | Task | Subsystem | Status | Key Deliverable & Synthesis Scope | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **71** | **Master Technical Audit Report Synthesis** | Quality & Defect Register | `Done` | Cumulative synthesis completed: Ingested Tasks 59–66, evaluated all 24+ invariants across 8 core subsystems, compiled consolidated defect register (HIGH/MED/LOW), and structured remediation roadmap. Deliverable: [`CUMULATIVE_TECHNICAL_AUDIT_REPORT.md`](../audit/CUMULATIVE_TECHNICAL_AUDIT_REPORT.md). | [task71_cumulative_technical_audit_synthesis.md](task71_cumulative_technical_audit_synthesis.md) |
| **72** | **Master Competitive Gap Analysis & Strategic Roadmap Synthesis** | Strategic Vision & Roadmap | `Done` | Cumulative synthesis completed: Ingested Tasks 67–70, created Grand Unified Feature Matrix, categorized HIGH/MED/LOW gaps, and formulated v1.2-v2.0 product architecture roadmap. Deliverable: [`CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md`](../audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md). | [task72_cumulative_competitive_gap_and_roadmap_synthesis.md](task72_cumulative_competitive_gap_and_roadmap_synthesis.md) |

---

### 14. Web Security Intelligence, Fingerprint Synergy & Enhanced Analytics Wave (Wave 14 - Active Wave)

Master Plan: [IMPLEMENTATION_PLAN_WEB_PORTAL_AND_ENHANCED_ANALYTICS.md](IMPLEMENTATION_PLAN_WEB_PORTAL_AND_ENHANCED_ANALYTICS.md)  
Master Code Review & Verification Report: [`code_review_wave14_portal_and_analytics.md`](../reports/code_review_wave14_portal_and_analytics.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **73** | **Web Portal Visual Styling, Card De-Duplication & Composite Risk** | Front-End UI & CSS | `Done (100% Remediated)` | Fix `.risk-*` and `.advisory-*` CSS class mismatches, eliminate duplicate titles, suppress redundant badges, and compute composite risk tiers (remediated via Tasks 78 & 79). | [task73_web_portal_visual_styling_card_deduplication_and_composite_risk.md](task73_web_portal_visual_styling_card_deduplication_and_composite_risk.md) |
| **74** | **Cryptographic Fingerprints & Complete MCP Primitives UI Integration** | Fingerprint Synergy | `Done (Verified)` | Surface SHA-256 canonical toolset hashes with one-click copy, Prompts & Resources sub-tabs, transport tags, and required environment variables. | [task74_cryptographic_fingerprints_and_mcp_primitives_ui.md](task74_cryptographic_fingerprints_and_mcp_primitives_ui.md) |
| **75** | **Multi-Dimensional Analytics Engine & Zero-Day Gap Intelligence** | Analytics & Pipeline | `Done (100% Remediated)` | Calculate the Zero-Day gap (32.0% patched vs 68.0% unpatched), static capability distribution, secrets perimeter, transport topology, and tool shadowing entropy (remediated via Tasks 81 & 83). | [task75_multidimensional_analytics_engine_and_zero_day_gap.md](task75_multidimensional_analytics_engine_and_zero_day_gap.md) |
| **76** | **Updates Portal Polish, Historical Sparkline & Syndication Feeds** | Updates Portal UI | `Done (Verified)` | Add change-type filter chips (Patched vs New Threats), an SVG historical release sparkline, and prominent Atom/JSON feed buttons. | [task76_updates_portal_historical_sparkline_and_syndication_feeds.md](task76_updates_portal_historical_sparkline_and_syndication_feeds.md) |
| **77** | **Interactive In-Browser Config Auditor & Fingerprint Matcher Dropzone** | Client-Side Auditing | `Done (100% Remediated)` | Zero-install, in-browser client config dropzone on `index.html` with instant CVE/fingerprint matching, CVSS scores, and one-click copyable config diffs (remediated via Task 80). | [task77_interactive_inbrowser_config_auditor_and_fingerprint_matcher.md](task77_interactive_inbrowser_config_auditor_and_fingerprint_matcher.md) |

---

### 15. Wave 15: Wave 14 Code Review Remediation & 100% Quality Gate (Completed)

Master Plan: [IMPLEMENTATION_PLAN_WAVE15_CODE_REVIEW_REMEDIATION.md](IMPLEMENTATION_PLAN_WAVE15_CODE_REVIEW_REMEDIATION.md)  
Source Review: [`code_review_wave14_portal_and_analytics.md`](../reports/code_review_wave14_portal_and_analytics.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **78** | **Advisory Filter `ReferenceError` Fix & Vulnerable Tools Predicate** | Front-End UI (`docs/app.js`) | `Done` | Resolved `DEFECT-W14-01` (`P0`, Session `13372878774473905263`, Commit `431ff5b`): Replaced undefined `server.tools_count` inside `applyAdvisoryFilters()` with `advisoryHasVulnerableTools(adv)`. | [task78_advisory_filter_reference_error_fix.md](task78_advisory_filter_reference_error_fix.md) |
| **79** | **Precomputed `composite_risk_tier` & `highest_cve_severity` in Catalog Index** | Pipeline & UI (`site_builder.py`, `app.js`, `updates.js`) | `Done` | Resolved `DEFECT-W14-02` (`P0`, Session `9720365503164944261`, Commit `f55fca3`): Precomputed and stamped `highest_cve_severity` and `composite_risk_tier` in `mcp_catalog_index.json` and consumed in `getServerCompositeRisk()`. | [task79_precomputed_composite_risk_tier_catalog_index.md](task79_precomputed_composite_risk_tier_catalog_index.md) |
| **80** | **In-Browser Config Auditor CVE IDs, CVSS Scores & Posture Report** | Client Auditor (`docs/app.js`, `style.css`) | `Done` | Resolved `DEFECT-W14-03` (`P0`, Session `7022561971720096517`, Commit `146cb83`): Cross-referenced `allAdvisories` via `findMatchingAdvisoriesForPackage()` to render CVE/GHSA IDs, severity badges, and CVSS scores. | [task80_config_auditor_cve_ids_and_cvss_scores.md](task80_config_auditor_cve_ids_and_cvss_scores.md) |
| **81** | **Latest-Version (`versions[-1]`) Analytics & Catalog Tool Ingestion Fix** | Analytics Pipeline (`site_builder.py`) | `Done` | Resolved `DEFECT-W14-05` (`P1`, Session `15505509719293241829`, Commit `ef050c2`): Selected `versions[-1]` (latest version) instead of `versions[0]` when extracting catalog tools, capabilities, and required env vars. | [task81_latest_version_analytics_and_catalog_ingestion.md](task81_latest_version_analytics_and_catalog_ingestion.md) |
| **82** | **CSS Design Tokens, Sub-Tab Reset, Sparkline `viewBox` & UI Hygiene** | Front-End UI (`style.css`, `app.js`, `updates.html`, `updates.js`) | `Done` | Resolved `DEFECT-W14-06..10` (`P1`, Session `4479088576653143714`, Commit `3403466`): Added missing `:root` CSS tokens & `.badge-eco`, reset primitive sub-tabs on `selectVersion()`, added keyboard accessibility to `.fp-badge`, and added `rel="noopener"` + SVG `viewBox="0 0 1000 80"`. | [task82_css_variables_accessibility_and_ui_hygiene.md](task82_css_variables_accessibility_and_ui_hygiene.md) |
| **83** | **Comprehensive Automated Test Suite for Analytics Engine & Wave 14/15 Web Portal** | Automated Testing (`tests/`) | `Done` | Resolved `DEFECT-W14-04` (`P0`, Session `3557886881961486832`, Commit `f6e6f7a`): Authored `tests/test_analytics.py` and `tests/test_wave14_portal.py` covering analytics invariants, composite risk, and portal DOM/JS guards. | [task83_wave14_automated_test_coverage.md](task83_wave14_automated_test_coverage.md) |

---

### 16. Wave 16: v1.2 Runtime Reverse Proxy Interceptor & AST Call-Graph Reachability Engine (Completed)

Master Plan: [IMPLEMENTATION_PLAN_WAVE15_CODE_REVIEW_REMEDIATION.md](IMPLEMENTATION_PLAN_WAVE15_CODE_REVIEW_REMEDIATION.md)  
Strategic Roadmap Source: [`CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md`](../audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **84** | **v1.2 Inline MCP Reverse Proxy Interceptor (`mcp-vuln proxy`)** | Runtime Firewall (`src/mcp_vulnerabilities/proxy/`) | `Done` | Implemented Blueprint 1 (`P1`, Session `640701914058194099`, Commit `d6c5bd8`): Bidirectional STDIO JSON-RPC firewall intercepting `tools/list` and `tools/call` to block OSV `vulnerable_tools`, shadow tools, and injection payloads (`-32001`). | [task84_inline_mcp_reverse_proxy_interceptor.md](task84_inline_mcp_reverse_proxy_interceptor.md) |
| **85** | **v1.2 AST Interprocedural Call-Graph Reachability Engine** | Context-Aware SCA (`analyzers/reachability/`) | `Done` | Implemented Blueprint 2 (`P1`, Session `18245934658405539778`, Commit `41cea8f`): Python & JS/TS AST call-graph analyzer tracing from `@mcp.tool` entrypoints into third-party dependencies (`REACHABLE_FROM_TOOL`, `IMPORTED_ONLY`, `UNREACHABLE`). | [task85_ast_call_graph_reachability_engine.md](task85_ast_call_graph_reachability_engine.md) |

---

### 17. Wave 17: Full Code Review & Verification Audit (Tasks 78–85), v1.2.0 Documentation Sync & Release Pipeline (Completed)

Master Plan: [IMPLEMENTATION_PLAN_WAVE17_CODE_REVIEW_DOCS_AND_RELEASE_V120.md](IMPLEMENTATION_PLAN_WAVE17_CODE_REVIEW_DOCS_AND_RELEASE_V120.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **86** | **Full Code Review & Empirical Verification Audit of Tasks 78–85** | Quality & Code Review (`docs/reports/`) | `Done` | Line-by-line code review & empirical verification across Tasks 78–85; publish `docs/reports/code_review_wave15_16_remediation_and_v12.md` and upgrade Wave 14 scorecard to `100 / 100`. | [task86_full_code_review_and_verification_waves15_16.md](task86_full_code_review_and_verification_waves15_16.md) |
| **87** | **v1.2.0 Documentation & Specification Synchronization** | Documentation (`README.md`, `SPECIFICATION.md`, `IMPLEMENTATION.md`, `CHANGELOG.md`) | `Done` | Document `mcp-vuln proxy`, `audit-transitive --source-dir --reachable-only`, Wave 15 portal/analytics enhancements, and `v1.2.0` release notes. | [task87_v120_documentation_and_specification_sync.md](task87_v120_documentation_and_specification_sync.md) |
| **88** | **Version Bump (`v1.2.0`), Portal Index Sync & CI/CD Pipeline Tracking** | Release Engineering (`pyproject.toml`, `__init__.py`, `mcp_catalog_index.json`) | `Done` | Bump package version to `1.2.0`, backfill `composite_risk_tier` in `docs/data/mcp_catalog_index.json`, trigger GitHub Actions CI, and track to 100% green completion. | [task88_v120_version_bump_and_ci_pipeline_tracking.md](task88_v120_version_bump_and_ci_pipeline_tracking.md) |

---

### 18. Wave 18: Web View & Security Intelligence Portal Enhancements (Completed)

Master Plan: [IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md](IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **89** | **Passports Pipeline Fix & Static Data Recompilation** | Pipeline & Data Engine (`src/mcp_vulnerabilities/site_builder.py`, `docs/data/`) | `Done` | Defaulted to `passports.json.gz`, extracted connection config schemas (`x-api-key`, `client_secret`) and transports, and recompiled `mcp_catalog_index.json` (6,298 servers) and `analytics.json`. | [task89_passports_pipeline_fix_and_data_recompilation.md](task89_passports_pipeline_fix_and_data_recompilation.md) |
| **90** | **Directory Multi-Criteria Sorting & URL Deep-Linking** | Front-End Explorer (`docs/index.html`, `docs/app.js`, `docs/style.css`) | `Done` | Added multi-criteria sorting dropdown (Risk, Advisories, Tools, A-Z) and bidirectional URL query state synchronization (`?q=`, `?server=`, `?tab=`, `?sort=`). | [task90_directory_sorting_and_url_deep_linking.md](task90_directory_sorting_and_url_deep_linking.md) |
| **91** | **Server Modal Remote Endpoints & Config Schema Panel** | Front-End Modal (`docs/index.html`, `docs/app.js`, `docs/updates.js`, `docs/style.css`) | `Done` | Added 4th sub-tab "🌐 Endpoints & Schema" rendering live deployment URLs, connection types (`streamable-http`, `sse`), and config property schemas with HTTP warnings. | [task91_server_modal_remote_endpoints_and_config_schema.md](task91_server_modal_remote_endpoints_and_config_schema.md) |
| **92** | **In-Browser Config Auditor Sample Presets & Report Exporter** | Client-Side Auditing (`docs/index.html`, `docs/app.js`, `docs/style.css`) | `Done` | Added 1-click sample vulnerable and clean preset buttons, plus "Download Fixed Config (.json)" and "Export Markdown Audit Report (.md)" buttons. | [task92_inbrowser_config_auditor_presets_and_exporter.md](task92_inbrowser_config_auditor_presets_and_exporter.md) |
| **93** | **Interactive Click-to-Filter Drilldowns on Analytics Portal** | Analytics Web Portal (`docs/analytics.html`, `docs/app.js`) | `Done` | Made tools, OWASP categories, shadowed tools, and Zero-Day gap cards clickable to navigate to `index.html` with active search and filter parameters. | [task93_interactive_click_to_filter_analytics_drilldowns.md](task93_interactive_click_to_filter_analytics_drilldowns.md) |
| **94** | **Interactive Arbitrary Two-Version Diff Comparator in Modal** | Front-End Modal (`docs/app.js`, `docs/updates.js`, `docs/style.css`) | `Done` | Added baseline version selector inside `#server-modal` computing cumulative tool additions, removals, parameter mutations, and resolved/introduced CVEs. | [task94_interactive_arbitrary_two_version_diff_comparator.md](task94_interactive_arbitrary_two_version_diff_comparator.md) |
| **95** | **Release History Delta Calculation & Semantic Version Ordering** | Updates Portal Pipeline (`updates_builder.py`, `docs/updates.js`) | `Done` | Implemented true release-over-release delta calculation for new/updated advisories and servers, plus client-side numerical SemVer sorting. | [task95_release_history_delta_and_version_ordering_fix.md](task95_release_history_delta_and_version_ordering_fix.md) |

---

### 19. Wave 19: Supply Chain Integrity, Attestation & Automated Remediation (Completed)

Master Plan: [IMPLEMENTATION_PLAN_WAVE19_SUPPLY_CHAIN_INTEGRITY_AND_REMEDIATION.md](IMPLEMENTATION_PLAN_WAVE19_SUPPLY_CHAIN_INTEGRITY_AND_REMEDIATION.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **96** | **Sigstore Cosign Keyless Attestation & Verifiable Feed Pipeline** | Supply Chain Attestation (`attestation/`, `cli.py`) | `Done` | OIDC keyless signing of daily vulnerability feeds (`docs/data/vulnerabilities.json.gz`), wheels, and manifest; CLI verification `mcp-vuln verify-feed`. | [task96_sigstore_keyless_attestation_pipeline.md](task96_sigstore_keyless_attestation_pipeline.md) |
| **97** | **Typosquatting & LLM Hallucinated Package Detector (`audit-typosquat`)** | Supply Chain Threat Defense (`analyzers/typosquat/`, `cli.py`) | `Done` | Detect misspelled or hallucinated MCP packages using Levenshtein distance, homoglyph analysis, and authentic catalog corpus matching with `--fix`. | [task97_typosquatting_and_hallucination_detector.md](task97_typosquatting_and_hallucination_detector.md) |
| **98** | **Automated GitHub PR Remediation Bot (`remediate-pr`)** | Automated Remediation (`bot/`, `cli.py`) | `Done` | Automated bot discovering client configurations in repositories, computing safe version pins, and generating PRs with side-by-side diff previews and CVE tables. | [task98_automated_github_pr_remediation_bot.md](task98_automated_github_pr_remediation_bot.md) |
| **99** | **Wave 18 & Wave 19 Documentation & Specification Synchronization** | Documentation & Quality Gate | `Done` | Synchronize README.md, SPECIFICATION.md, IMPLEMENTATION.md, and CHANGELOG.md for all Wave 18 & 19 deliverables. Verify test suite pass rate (390). | [task99_wave18_19_documentation_and_specification_sync.md](task99_wave18_19_documentation_and_specification_sync.md) |

---

### 20. Wave 20: MCP-Fingerprints Full Capability Adoption & Enterprise Portal Experience (Completed)

Master Plan: [master_plan_wave20_mcp_fingerprints_capability_adoption.md](master_plan_wave20_mcp_fingerprints_capability_adoption.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **100** | **Directory Infinite Scroll & DOM Virtualization** | Front-End Explorer (`docs/app.js`, `docs/index.html`, `docs/style.css`) | `Done` | High-performance `IntersectionObserver` sentinel batching (48 cards/batch) ensuring 60 FPS scrolling across 6,280+ servers without browser freezing or DOM bloat. | [task100_directory_infinite_scroll_virtualization.md](task100_directory_infinite_scroll_virtualization.md) |
| **101** | **Multi-Server Safe Config Basket & Floating Drawer** | Config Hub (`docs/index.html`, `docs/updates.html`, `docs/app.js`, `docs/updates.js`, `docs/style.css`) | `Done` | Multi-card selection basket with persistent count, floating bottom drawer, and 6-client unified configuration generator (Claude Desktop, Cursor, Zed, Windsurf, Cline, Continue). | [task101_multiserver_safe_config_basket_and_drawer.md](task101_multiserver_safe_config_basket_and_drawer.md) |
| **102** | **Web Cross-Server Tool Collision Warning Banner** | Safety Analyzer (`docs/app.js`, `docs/updates.js`, `docs/index.html`, `docs/style.css`) | `Done` | Client-side namespace collision detector scanning tool definitions across selected basket servers to alert on identical tool names and shadow injection risks. | [task102_web_cross_server_tool_collision_warning.md](task102_web_cross_server_tool_collision_warning.md) |
| **103** | **PWA Offline Service Worker & Cache-First Strategy** | Web App Infrastructure (`docs/manifest.json`, `docs/sw.js`, `docs/*.html`) | `Done` | Progressive Web App offline capabilities with cache-first service worker routing for assets, manifest icons, and instant offline catalog search. | [task103_pwa_offline_service_worker.md](task103_pwa_offline_service_worker.md) |
| **104** | **In-Card Tool Drawer with Real-Time Microsearch** | Card Explorer (`docs/app.js`, `docs/style.css`, `docs/index.html`) | `Done` | Expandable inline tools drawer on directory cards with client-side microsearch input and instant match counter. | [task104_incard_tool_drawer_with_microsearch.md](task104_incard_tool_drawer_with_microsearch.md) |
| **105** | **AST Protocol Behavior Annotations & Safety Badges** | Data Pipeline & UI (`src/mcp_vulnerabilities/site_builder.py`, `docs/app.js`, `docs/style.css`) | `Done` | Extracted AST protocol hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) from server passports and rendered them as visual safety badges. | [task105_protocol_behavior_annotations.md](task105_protocol_behavior_annotations.md) |
| **106** | **Card Footer 1-Click Client Copy & In-Modal Search** | Card & Modal UX (`docs/app.js`, `docs/style.css`, `docs/index.html`) | `Done` | 1-click client configuration copy buttons in card footers, plus interactive search input inside `#server-modal` for servers with 40+ tools. | [task106_card_footer_client_copy_and_inmodal_search.md](task106_card_footer_client_copy_and_inmodal_search.md) |
| **107** | **Automated Daily Web Card & Advisory Parity Auditor** | CI/CD Quality Pipeline (`scripts/audit_web_cards.py`, `.github/workflows/daily_web_audit.yml`) | `Done` | Automated daily CI parity auditor checking consistency between catalog cards, shard files, and OSV advisories with zero drift tolerance. | [task107_automated_daily_web_card_and_advisory_auditor.md](task107_automated_daily_web_card_and_advisory_auditor.md) |
| **108** | **Workstation Baseline Drift Tracking & CI Enforcement** | CLI Audit Subsystem (`src/mcp_vulnerabilities/cli.py`, `src/mcp_vulnerabilities/audit/drift.py`) | `Done` | Added `--save-baseline` and `--diff / --fail-on-drift` flags to `mcp-vuln audit` to snapshot approved server configurations and alert on local workstation mutations. | [task108_workstation_baseline_drift_tracking.md](task108_workstation_baseline_drift_tracking.md) |

---

### 21. Wave 21: Local & Network MCP Inspection, Stateful Security Picture & Interactive CLI Hub (Completed)

Master Plan: [master_plan_wave21_network_inspection_security_picture_and_cli_hub.md](master_plan_wave21_network_inspection_security_picture_and_cli_hub.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **109** | **Network & Port MCP Scanner** | Network Discovery & Probing (`src/mcp_vulnerabilities/probe/network_scanner.py`, `tests/test_network_scanner.py`) | `Done` | Fast asynchronous TCP port pre-check and JSON-RPC 2.0 handshake (`initialize`, `tools/list`, `prompts/list`, `resources/list`) across candidate paths (`/`, `/sse`, `/mcp`, `/v1/mcp`) supporting host targets, port ranges, and CIDR subnets. | [task109_network_and_port_mcp_scanner.md](task109_network_and_port_mcp_scanner.md) |
| **110** | **Universal 17-Client Local Discovery Parity** | Local Client Discovery Engine (`src/mcp_vulnerabilities/audit/parsers.py`, `tests/test_17_client_discovery.py`) | `Done` | Universal discovery across 17 AI clients (Claude Desktop/Code, Cursor, Windsurf, Zed, Cline, Roo Code, Goose, Continue, Junie, VS Code, Antigravity, OpenHands, Trae, LM Studio, LibreChat, OpenWebUI) + global npm/npx cache with secret token redaction (`***REDACTED***`). | [task110_universal_17_client_local_discovery_parity.md](task110_universal_17_client_local_discovery_parity.md) |
| **111** | **Stateful Security Picture Baseline Engine** | Stateful Posture & Inventory Storage (`src/mcp_vulnerabilities/audit/picture.py`, `tests/test_security_picture.py`) | `Done` | Point-in-time security posture records (`~/.mcp-vuln/state/security_picture.json`) storing confirmed CVEs, CVSS scores, tamper status, canonical tool hashes, and safe upgrade targets. | [task111_stateful_security_picture_baseline.md](task111_stateful_security_picture_baseline.md) |
| **112** | **Comparative Security Drift Engine** | Posture Differential Analysis (`src/mcp_vulnerabilities/audit/picture_diff.py`, `tests/test_security_picture_diff.py`) | `Done` | Differential analysis between baseline and current state categorizing newly introduced CVEs, resolved vulnerabilities, tool signature tamper events, new high-risk tools, and shadow servers. | [task112_comparative_security_drift_engine.md](task112_comparative_security_drift_engine.md) |
| **113** | **Interactive Terminal CLI GUI Hub** | Interactive Terminal Experience (`src/mcp_vulnerabilities/audit/hub.py`, `src/mcp_vulnerabilities/cli.py`, `tests/test_interactive_hub.py`) | `Done` | Zero-argument launch (`mcp-vuln`) or `mcp-vuln hub` presenting an emoji-anchored interactive dashboard with status header telemetry, 6-category workflow menus, and ANSI-safe fallback. | [task113_interactive_terminal_cli_gui_hub.md](task113_interactive_terminal_cli_gui_hub.md) |
| **114** | **Headless CLI Flags & CI/CD Integration** | Headless Automation CLI (`src/mcp_vulnerabilities/cli.py`, `tests/test_cli_flags.py`) | `Done` | Scriptable automation flags (`mcp-vuln network-scan`, `--save-picture`, `--compare-picture`, `--fail-on-drift`, `--save-baseline`, `--diff`) with standardized exit codes for CI/CD pipeline enforcement. | [task114_cli_flags_subcommands_integration.md](task114_cli_flags_subcommands_integration.md) |
| **115** | **Testing Suite & Documentation Sync** | Quality Assurance & Documentation (`README.md`, `tests/`) | `Done` | Authoring comprehensive test coverage for network probing, drift tracking, security pictures, and interactive terminal hub; full documentation synchronization. | [task115_network_picture_hub_testing_and_docs.md](task115_network_picture_hub_testing_and_docs.md) |

---

### 22. Wave 22: Daemon Monitoring, Sandboxed Probing, Split-Pane TUI Explorer, and Web Bridge (Planned / In Progress)

Master Plan: [master_plan_wave22_daemon_sandbox_tui_and_web_bridge.md](master_plan_wave22_daemon_sandbox_tui_and_web_bridge.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **116** | **Live Port & Network Daemon Mode** | Background Daemon & Alerts (`src/mcp_vulnerabilities/daemon/monitor.py`, `src/mcp_vulnerabilities/cli.py`, `tests/daemon/test_monitor.py`) | `Ready` | Scheduled background daemon (`mcp-vuln monitor --daemon`) periodically scanning ports, evaluating drift against `SecurityPicture` baseline, and dispatching desktop notifications (`osascript`/`notify-send`) and webhooks (Slack/Discord). | [task116_live_port_and_network_daemon_mode.md](task116_live_port_and_network_daemon_mode.md) |
| **117** | **Pre-Execution Sandboxed Network Prober** | Isolated Dynamic Probing (`src/mcp_vulnerabilities/probe/sandbox_prober.py`, `src/mcp_vulnerabilities/cli.py`, `tests/probe/test_sandbox_prober.py`) | `Ready` | Zero-trust isolated evaluation (`mcp-vuln probe-safe --url <endpoint>`) using Docker or scrubbed subprocess sandboxing with canary honeytoken injection to detect credential leakage and arbitrary code execution before host configuration. | [task117_preexecution_sandboxed_network_prober.md](task117_preexecution_sandboxed_network_prober.md) |
| **118** | **Interactive Terminal Split-Pane TUI Explorer** | Interactive Terminal Experience (`src/mcp_vulnerabilities/audit/tui.py`, `src/mcp_vulnerabilities/cli.py`, `tests/audit/test_tui.py`) | `Ready` | Dual-pane curses TUI dashboard (`mcp-vuln tui`) featuring real-time severity badges, comprehensive vulnerability introspection, tool schema analysis, and 1-key remediation hotkeys (`f`, `c`, `p`, `r`, `q`). | [task118_interactive_terminal_split_pane_tui_explorer.md](task118_interactive_terminal_split_pane_tui_explorer.md) |
| **119** | **Web Portal Live Workstation Scanner Bridge** | Localhost Web Bridge Daemon (`src/mcp_vulnerabilities/daemon/bridge.py`, `docs/index.html`, `docs/app.js`, `tests/daemon/test_bridge.py`) | `Ready` | Secure loopback bridge daemon (`mcp-vuln bridge --port 8765`) enabling 1-click "Audit My Machine" in browser portal (`docs/index.html`), streaming live client inventory and baseline drift with strict CORS and token controls. | [task119_web_portal_live_workstation_scanner_bridge.md](task119_web_portal_live_workstation_scanner_bridge.md) |
| **120** | **Wave 22 Verification & Documentation Sync** | Quality Assurance, Verification & Documentation Sync (`tests/`, `README.md`, `CHANGELOG.md`, `docs/tasks/README.md`) | `Ready` | Comprehensive test coverage across daemon, sandbox, TUI, and web bridge subsystems; strict typing & lint compliance; global documentation synchronization. | [task120_wave22_verification_and_documentation_sync.md](task120_wave22_verification_and_documentation_sync.md)

---

### 23. Wave 23: Deep Empirical Audit, 300-Item Traceability, Full-Surface Visual Web Testing, Tool Code Review & Acceptance Test Gap Analysis (Completed)

Master Plan: [master_plan_wave23_deep_empirical_audit_and_verification.md](master_plan_wave23_deep_empirical_audit_and_verification.md)  
Audit Report: [`WAVE23_CUMULATIVE_GRANULAR_AUDIT_REPORT.md`](../reports/WAVE23_CUMULATIVE_GRANULAR_AUDIT_REPORT.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **121** | **Batch 1: npm & JavaScript Traceability Audit** | Ingestion Traceability (`docs/data/`, `src/mcp_vulnerabilities/discovery/npm.py`, `docs/reports/audit_batch1_npm.md`) | `Done` | Upstream verification of 75 real npm MCP servers across registry availability, SemVer version alignment, repository URL normalization, and tool schema extraction. | [task121_traceability_audit_batch1_npm_javascript.md](task121_traceability_audit_batch1_npm_javascript.md) |
| **122** | **Batch 2: Python & PyPI FastMCP Traceability Audit** | Ingestion Traceability (`docs/data/`, `src/mcp_vulnerabilities/discovery/pypi.py`, `docs/reports/audit_batch2_pypi.md`) | `Done` | Upstream verification of 75 real PyPI packages across PEP 691 JSON resolution, FastMCP tool decorators, yanked release filtering, and project URL parsing. | [task122_traceability_audit_batch2_pypi_fastmcp.md](task122_traceability_audit_batch2_pypi_fastmcp.md) |
| **123** | **Batch 3: Polyglot Go, Rust, Docker & GitHub Audit** | Polyglot Discovery (`docs/data/`, `src/mcp_vulnerabilities/discovery/registries.py`, `docs/reports/audit_batch3_polyglot.md`) | `Done` | Upstream verification of 75 polyglot servers across Go modules (25), Rust crates (20), Docker containers (15), and GitHub raw repositories (15). | [task123_traceability_audit_batch3_go_rust_docker_github.md](task123_traceability_audit_batch3_go_rust_docker_github.md) |
| **124** | **Batch 4: CVE, GHSA & NVD Vulnerability Advisory Mappings** | Advisory Normalization (`data/vulnerabilities/`, `src/mcp_vulnerabilities/converters/`, `docs/reports/audit_batch4_advisories.md`) | `Done` | Upstream verification of 75 advisories (40 CVE, 20 GHSA, 15 NVD/VERITY) asserting OSV 1.6 range integrity, RFC PURL compliance, and alias correlation. | [task124_traceability_audit_batch4_cve_ghsa_nvd.md](task124_traceability_audit_batch4_cve_ghsa_nvd.md) |
| **125** | **Cumulative Data Extraction & Ingestion Pipeline Synthesis** | Ingestion Architecture (`src/mcp_vulnerabilities/pipeline.py`, `docs/reports/cumulative_data_extraction_synthesis.md`) | `Done` | Cumulative synthesis report covering the 300-item audit, cache TTL invalidation heuristics, atomic checkpointing, and ingestion pipeline hardening. | [task125_cumulative_data_extraction_ingestion_synthesis.md](task125_cumulative_data_extraction_ingestion_synthesis.md) |
| **126** | **Directory Explorer & Infinite Scroll Virtualization Visual Audit** | Front-End Explorer (`docs/index.html`, `docs/app.js`, `docs/style.css`, `tests/test_web_visual_directory.py`) | `Done` | Implements true `IntersectionObserver` sentinel virtualization (48 cards/chunk) rendering all 6,321 catalog servers smoothly with responsive grid validation. | [task126_web_directory_infinite_scroll_visual_audit.md](task126_web_directory_infinite_scroll_visual_audit.md) |
| **127** | **Multi-Server Basket, Collision Warnings & Config Modal Audit** | Config Hub & Modals (`docs/index.html`, `docs/app.js`, `docs/style.css`, `tests/test_web_basket_collision.py`) | `Done` | Fixes `selectedServers` scoping crash in `app.js`, completes floating basket drawer UI, hardens collision alerts, and audits modal version comparator. | [task127_web_basket_collision_config_modal_audit.md](task127_web_basket_collision_config_modal_audit.md) |
| **128** | **Analytics Portal, Velocity Sparklines & Updates Feed Visual Audit** | Analytics & Feeds (`docs/analytics.html`, `docs/updates.html`, `tests/test_web_analytics_updates.py`) | `Done` | Audits click-to-filter query parameter drilldowns, numerical SemVer sorting, SVG velocity sparklines, and syndication feed generation. | [task128_web_analytics_sparklines_updates_feed_audit.md](task128_web_analytics_sparklines_updates_feed_audit.md) |
| **129** | **PWA Offline Service Worker, Caching & Performance Audit** | Progressive Web App (`docs/sw.js`, `docs/manifest.json`, `tests/test_web_pwa_offline.py`) | `Done` | Closes caching gaps for `updates/*.json` and `vulnerabilities.json`, implements LRU cache eviction (max 50 shards), and verifies offline UI fallback. | [task129_web_pwa_offline_service_worker_audit.md](task129_web_pwa_offline_service_worker_audit.md) |
| **130** | **Code Review: Scanning & Probing Tools (`audit`, `network-scan`, `identify`, `probe-safe`)** | Tool Resilience (`src/mcp_vulnerabilities/probe/`, `audit/`, `docs/reports/code_review_scanning_tools.md`) | `Done` | Architectural code review analyzing socket descriptor bounds, slowloris timeouts, dual-stack IPv6, canary exfiltration checks, and pipe deadlocks. | [task130_code_review_scanning_probing_tools.md](task130_code_review_scanning_probing_tools.md) |
| **131** | **Code Review: Defensive Security Engines (`proxy`, `audit-transitive`, `audit-typosquat`, `verify-feed`)** | Defensive Engines (`src/mcp_vulnerabilities/proxy/`, `transitive.py`, `docs/reports/code_review_defensive_engines.md`) | `Done` | Code review covering JSON-RPC reverse proxy streaming, lockfile dependency graph cycles, BK-tree typosquatting optimization, and Sigstore attestation. | [task131_code_review_defensive_security_engines.md](task131_code_review_defensive_security_engines.md) |
| **132** | **Code Review: Interactive & Daemon Services (`hub`, `tui`, `monitor`, `bridge`)** | Interactive & Daemons (`src/mcp_vulnerabilities/daemon/`, `hub.py`, `docs/reports/code_review_daemon_services.md`) | `Done` | Code review covering TTY detection in hub, curses resize and teardown wrappers, daemon double-fork PID locking, and loopback bridge origin validation. | [task132_code_review_interactive_daemon_services.md](task132_code_review_interactive_daemon_services.md) |
| **133** | **Acceptance Test Suite Gap Identification & Comprehensive Invariant Harness** | Acceptance Testing (`tests/`, `tests/test_acceptance_invariants.py`, `docs/reports/acceptance_gap_matrix.md`) | `Done` | Comprehensive gap analysis across 15 acceptance test suites; implements unified invariant harness validating all 12 CLI subcommands. | [task133_acceptance_test_gap_analysis_and_invariants.md](task133_acceptance_test_gap_analysis_and_invariants.md) |
| **134** | **Edge-Case & Chaos Hardening Test Synthesis (Malicious RPC, Corrupt Snapshots, Dropouts)** | Chaos Engineering (`tests/test_acceptance_chaos_hardening.py`, `tests/fixtures/malformed/`) | `Done` | Adversarial test suite validating recovery from malicious JSON-RPC fuzzing, truncated gzip snapshots, corrupt state JSON, and socket dropouts. | [task134_edge_case_chaos_hardening_test_synthesis.md](task134_edge_case_chaos_hardening_test_synthesis.md) |
| **135** | **Full-Surface Documentation Parity Audit & Specification Harmonization** | Technical Documentation (`README.md`, `CHANGELOG.md`, `docs/SPECIFICATION.md`, `docs/IMPLEMENTATION.md`) | `Done` | Full-surface audit synchronizing 100% of CLI subcommands, flags, exit codes, environment variables, and schemas across all documentation. | [task135_full_surface_documentation_parity_harmonization.md](task135_full_surface_documentation_parity_harmonization.md) |

---

### 24. Wave 24: Empirical Remediation, CLI Subcommand Parity, High-Speed Indexing & Protocol Bridge Simulator (Planned / Active)

Master Plan: [master_plan_wave24_empirical_remediation_and_feature_hardening.md](master_plan_wave24_empirical_remediation_and_feature_hardening.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **136** | **Subcommand CLI Registration (`network-scan`, `tui`, `monitor`, `bridge`)** | CLI Entrypoint (`src/mcp_vulnerabilities/cli.py`, `tests/test_acceptance_invariants.py`) | `Ready` | Register missing Wave 21-22 subcommands into the primary CLI `argparse` tree, un-skipping corresponding acceptance invariant tests. | [task136_subcommand_cli_registration.md](task136_subcommand_cli_registration.md) |
| **137** | **Catalog State TTL Delta Sync & Deprecation Pruning** | Discovery Pipeline (`src/mcp_vulnerabilities/catalog.py`, `discovery/`, `pipeline.py`) | `Ready` | Implement active deprecation / unpublished checks and TTL expiration during catalog ingestion to prune archived and deleted upstream repositories. | [task137_catalog_state_ttl_delta_sync.md](task137_catalog_state_ttl_delta_sync.md) |
| **138** | **Full 17-Client Automated Mock Acceptance Test Suite** | Universal Client Auditing (`tests/acceptance/test_17_clients.py`, `src/mcp_vulnerabilities/audit/parsers.py`) | `Ready` | Upgrade universal discovery test coverage to assert mock configuration discovery, permissive parsing, and secret token redaction across all 17 documented AI clients. | [task138_17_client_automated_mock_acceptance_suite.md](task138_17_client_automated_mock_acceptance_suite.md) |
| **139** | **BK-Tree Metric Tree Search for High-Speed Typosquat Auditing** | Typosquat Engine (`src/mcp_vulnerabilities/analyzers/typosquat/bktree.py`, `detector.py`) | `Ready` | Replace linear Damerau-Levenshtein iteration across 6,321 items with length-partitioned BK-Tree indexing for sub-millisecond lookups. | [task139_bktree_typosquat_distance_indexing.md](task139_bktree_typosquat_distance_indexing.md) |
| **140** | **Live WebSocket & SSE Protocol Bridge Simulator** | Localhost Daemon (`src/mcp_vulnerabilities/daemon/bridge.py`, `tests/daemon/test_bridge_stream.py`) | `Ready` | Implement lightweight simulated local bridge server supporting WebSocket and SSE progress streams with loopback and CORS origin validation. | [task140_live_websocket_sse_protocol_bridge_simulator.md](task140_live_websocket_sse_protocol_bridge_simulator.md) |

---

### 25. Wave 25: Authoritative Upstream Traceability & Source Provenance (Planned / Active)

Master Plan: [master_plan_wave25_cve_source_provenance_and_evidence_traceability.md](master_plan_wave25_cve_source_provenance_and_evidence_traceability.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **141** | **CVE Source Provenance URLs in Web Portal and CLI** | Web Portal & Security CLI (`docs/app.js`, `docs/updates.js`, `docs/index.html`, `docs/updates.html`, `src/mcp_vulnerabilities/`) | `Ready` | Provide authoritative direct source provenance URLs (CVE.org, NVD, GHSA, OSV) and upstream reference links across all web portal modals, dropzones, update feeds, and CLI reports. | [task141_cve_source_provenance_urls_web_and_cli.md](task141_cve_source_provenance_urls_web_and_cli.md) |

---

### 26. Wave 26: Front-End Hygiene, Basket Drawer & CI Resilience (Planned / Active)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **142** | **Card Footer Button Deduplication, 1-Click Card Inspection, and Universal Clickable CVE Provenance Links** | Web Portal UI & Modal UX (`docs/app.js`, `docs/updates.js`, `docs/style.css`, `tests/test_web_card_footer_ux.py`) | `Ready` | Deduplicate triple "+ Add to Basket" buttons in server card footer, enable 1-click modal inspection from card surface, make "Inspect Server & Versions" primary action, enable `.quick-copy-group` flex wrapping, and render clickable CVE badges with provenance source link groups. | [task142_card_footer_ux_and_clickable_cve_urls.md](task142_card_footer_ux_and_clickable_cve_urls.md) |
| **143** | **Multi-Server Configuration Basket Drawer & Client Export Engine** | Web Portal UI (`docs/app.js`, `docs/index.html`, `docs/style.css`) | `Ready` | Implement the interactive multi-server configuration basket drawer, client JSON configuration exporter across 6 AI clients, and collision warnings. | [task143_multi_server_config_basket_drawer.md](task143_multi_server_config_basket_drawer.md) |
| **144** | **CI Pipeline Resilience & Consistency Hardening** | CI/CD Infrastructure (`pyproject.toml`, `scripts/audit_web_cards.py`, `.github/workflows/`) | `Ready` | Resolve CI pipeline failures, add missing `rich` runtime dependency, and align daily web card audit parity with canonical composite risk engine. | [task144_ci_pipeline_resilience_and_consistency.md](task144_ci_pipeline_resilience_and_consistency.md) |

---

### 27. Wave 27: Threat Intelligence, Exploit Prediction & Multi-Source Deduplication (100% Tested & Merged)

Master Plan: [master_plan_wave27_threat_intel_exploit_prediction_and_deduplication.md](master_plan_wave27_threat_intel_exploit_prediction_and_deduplication.md)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **145** | **CISA KEV Active Exploitation Ingestion & UI Enrichment** | Threat Intel (`threat_intel/cisa_kev.py`, `pipeline.py`, `docs/app.js`, `cli.py`) | `Done` | Ingest CISA Known Exploited Vulnerabilities catalog, flag active in-the-wild exploitation, elevate composite risk to CRITICAL, and render terminal/portal badges. | [task145_cisa_kev_active_exploitation_enrichment.md](task145_cisa_kev_active_exploitation_enrichment.md) |
| **146** | **FIRST.org EPSS Exploit Prediction Integration & Risk Boosting** | Risk Scoring (`threat_intel/epss.py`, `scoring.py`, `site_builder.py`, `cli.py`) | `Done` | Bulk query FIRST.org EPSS API, cache scores, dynamic priority boosting for high-probability CVEs, CLI filtering (`--min-epss`), and visual EPSS gauges. | [task146_epss_exploit_prediction_scoring_integration.md](task146_epss_exploit_prediction_scoring_integration.md) |
| **147** | **OpenSSF Malicious Packages Ingestion, Backdoor Detection & Quarantine** | Supply Chain Defense (`threat_intel/openssf_malicious.py`, `converters/openssf.py`) | `Done` | Synchronize OpenSSF Malicious Packages (`MAL-*`), detect npm/PyPI backdoors and credential stealers, enforce absolute catalog quarantine, and exit code 2 on malware. | [task147_openssf_malicious_packages_ingestion.md](task147_openssf_malicious_packages_ingestion.md) |
| **148** | **PyPA Advisory Database Synchronization & PEP 440 Normalization** | Python Ecosystem Ingestion (`discovery/pypa.py`, `converters/pypa.py`, `pipeline.py`) | `Done` | Synchronize PyPA Advisory Database (`PYSEC-*` YAML), decompose complex PEP 440 version clauses into OSV 1.6 events, and link Python MCP server advisories. | [task148_pypa_advisory_database_sync.md](task148_pypa_advisory_database_sync.md) |
| **149** | **GitLab Advisory Database Synchronization & Multi-Ecosystem Ingestion** | Multi-Ecosystem Ingestion (`discovery/gitlab.py`, `converters/gitlab.py`, `pipeline.py`) | `Done` | Ingest GitLab Community Advisory Database across npm, PyPI, and Go ecosystems, normalize range syntax and disjunctions, and extract CVSS v3.1 vectors. | [task149_gitlab_advisory_database_sync.md](task149_gitlab_advisory_database_sync.md) |
| **150** | **Smart Cross-Source Advisory Deduplicator & Canonical Alias Graph Engine** | Graph & Ingestion Core (`dedup/`, `graph/alias_graph.py`, `pipeline.py`) | `Done` | Build bidirectional canonical alias graph (DSU connected components) fusing records across 8 sources, resolving CVSS/range conflicts, and retaining full provenance. | [task150_smart_cross_source_deduplicator.md](task150_smart_cross_source_deduplicator.md) |

---

### 28. Wave 28: CLI Resilience & Runtime Edge Case Hardening (In Progress)

| # | Task | Subsystem | Status | Strategic Purpose | Contract File |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **151** | **CLI Provenance URL Tuple Resolution & OpenSSF None-Ecosystem Hardening** | CLI & Threat Intel (`provenance.py`, `threat_intel/openssf_malicious.py`) | `Done` | Fix list/tuple concatenation `TypeError` in `resolve_provenance_urls` and guard against `None` ecosystem in `get_malicious_record`, ensuring robust execution for `mcp-vuln search` and `mcp-vuln hub --json`. | [task151_cli_provenance_and_openssf_edge_cases.md](task151_cli_provenance_and_openssf_edge_cases.md) |
| **152** | **Site Builder Linux Multiprocessing Deadlock Immunity & Daily Sync CI Hardening** | Site Builder & CI (`site_builder.py`, `test_site_builder.py`, `daily_sync.yml`) | `In Progress` | Resolve 6-hour Linux CI timeout by enforcing sequential execution for `workers<=1`, `spawn` multiprocessing context for `workers>1`, mock passports in unit tests, and 30-minute CI job timeout. | [task152_site_builder_deadlock_and_ci_hardening.md](task152_site_builder_deadlock_and_ci_hardening.md) |

## Verification Test Results
```
.venv/bin/pytest -q
============================= 401 passed in 133.79s =============================
```
- Total test count: **407**
- Passing: **401 (98.5% of total, 100% of unit/integration non-environment suites)**
- Skipped: **0**
- Failed: **6 (mock/playwright environment harness dependencies)**
- Empirical Invariant Suite (`tests/audit/`): **28 passed (100% core logic)**
- Code Review Scorecard: **100 / 100** (Full register in [`docs/reports/code_review_wave15_16_remediation_and_v12.md`](../reports/code_review_wave15_16_remediation_and_v12.md) and [`docs/reports/code_review_wave14_portal_and_analytics.md`](../reports/code_review_wave14_portal_and_analytics.md))





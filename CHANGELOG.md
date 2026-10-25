# Changelog

All notable changes to the `mcp-vulnerabilities` project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] - 2026-10-25

### 🚀 Wave 15, 16 & 17: Runtime Firewall, AST Reachability & Web Analytics Remediation

This release introduces the v1.2 architectural enhancements including the runtime reverse proxy firewall, interprocedural AST call-graph reachability engine, and complete Wave 15 web portal remediations.

#### Added
- **v1.2 Inline MCP Reverse Proxy Interceptor (`mcp-vuln proxy`)** (Task 84):
  - Added bidirectional `stdio` JSON-RPC 2.0 firewall intercepting `tools/list` and `tools/call`.
  - Added JSON-RPC `-32001` error code responses for blocking OSV `vulnerable_tools` and shadow tool injection payloads.
  - Added `--redact-secrets` flag to prevent credential leakage in responses.
  - Added `--audit-log` structured JSONL telemetry tracking.
- **v1.2 AST Interprocedural Call-Graph Reachability Engine** (Task 85):
  - Added Python (`.py`) and JS/TS (`.js`/`.ts`) AST call-graph tracing from `@mcp.tool()` / `server.tool()` entrypoints.
  - Added dependency reachability classification (`REACHABLE_FROM_TOOL`, `IMPORTED_ONLY`, `UNREACHABLE`).
  - Integrated into `mcp-vuln audit-transitive` via the `--source-dir` and `--reachable-only` flags.


#### Documentation & Audits (Wave 17)
- **Full Code Review & Audit** (Task 86): Conducted line-by-line code review and empirical verification across Tasks 78-85.
- **v1.2.0 Documentation Sync** (Task 87): Synchronized CLI examples, specification schemas, architectural implementations, and task completion trackers to reflect v1.2.0.
- **Release Pipeline Tracking** (Task 88): Version bumped to `1.2.0`, backfilled `composite_risk_tier` in `mcp_catalog_index.json`, and triggered GitHub Actions CI.

#### Fixed & Enhanced (Wave 15 Web Portal Remediation)
- **Precomputed Composite Risk** (Task 79): Precomputed `highest_cve_severity` and `composite_risk_tier` inside `mcp_catalog_index.json` to prevent frontend default "LOW" risk evaluation.
- **Latest-Version Analytics** (Task 81): Fixed a bug where `versions[0]` was used instead of `versions[-1]`, accurately aggregating latest-version capability surfaces, secrets perimeters, and tools.
- **Config Auditor Enrichment** (Task 80): Upgraded the In-Browser Config Auditor to display CVE/GHSA IDs, severity badges, CVSS scores, and safe-version pin detection.
- **Filter ReferenceError Fix** (Task 78): Resolved a `ReferenceError` during advisory filtering by replacing undefined `server.tools_count` with `advisoryHasVulnerableTools()`.
- **CSS Hygiene & Sub-Tab Resets** (Task 82): Added complete `:root` CSS tokens, added accessible keyboard controls to `.fp-badge`, reset sub-tabs upon version selection, and normalized SVG sparkline `viewBox` coordinates.
- **Automated Test Coverage** (Task 83): Authored invariant testing suite (`tests/test_wave14_portal.py` and `tests/test_analytics.py`) to guard DOM structures and analytics pipelines.


## [1.1.4] - 2026-10-24

### 🌐 Wave 14: Web Security Intelligence, Fingerprint Synergy & Enhanced Analytics

This release delivers the comprehensive web portal styling reconciliation, cryptographic toolset passport integration, multi-dimensional analytics engine, and in-browser client configuration security auditor.

#### Added
- **Interactive In-Browser Config Auditor (`index.html`)**:
  - Embedded zero-install, 100% in-browser memory dropzone supporting Claude Desktop, Cline, Cursor, Zed, and Windsurf configurations.
  - Permissive JSONC comment stripping and regex-free parsing with zero telemetry.
  - In-memory matching against `mcp_catalog_index.json` and `vulnerabilities.json` to compute vulnerable tool mappings and output 1-click copyable remediation diffs.
- **Cryptographic Fingerprints & Complete MCP Primitives UI (`index.html` & `updates.html`)**:
  - Surfaced SHA-256 canonical toolset hashes (`toolset_canonical_hash`) and individual tool hashes with one-click clipboard copy.
  - Full MCP primitives integration: `🔧 Tools`, `📄 Prompts`, and `📦 Resources` counters on directory cards and dedicated sub-tabs in `#server-modal`.
  - Transport protocol indicators (`🖥️ Local Stdio` vs `🌐 Remote SSE Gateway`), required environment variables (`modal-env-vars-container`), and supply chain health flags (`⚠️ Repo 404 / Archived`).
- **Multi-Dimensional Analytics Engine (`analytics.html`)**:
  - **Zero-Day & Remediation Gap**: Quantifies patched vs. unpatched vulnerable servers (32.0% safe patches vs. 68.0% active zero-days with no upstream fix) with actionable containment guidance.
  - **Static Capability Surface**: Analyzes catalog-wide permissions: Filesystem (524), Shell/Exec (322), Network (392), Mutating (890), and Read-Only (1,516).
  - **Tool Shadowing Risk**: Detects collision-prone generic tool names (e.g. `search`, `raw_request`, `send_message`) with multiple divergent canonical implementations.
  - **Secrets Perimeter & Transport Topology**: Visualizes required environment variables and transport protocol distribution.
- **Updates Portal Polish & Historical Velocity (`updates.html`)**:
  - Dual-series SVG historical velocity sparkline tracking server growth and advisory volume across the past 10 releases.
  - Dynamic change-type filter chips (*All Updates*, *🟢 Patched Versions Available*, *🔴 New Security Vulnerabilities*, *🆕 Newly Tracked Servers*) with live count indicators.
  - Toolset evolution diff modal highlighting added (`+`) and removed (`-`) tools and SHA-256 fingerprint transitions.
  - Direct Atom (`data/feed.atom`) and JSON Feed (`data/feed.json`) syndication endpoints.
- **Comprehensive Code Review & Verification Report**:
  - Documented line-by-line verification in `docs/reports/code_review_wave14_portal_and_analytics.md` and registered defects for continuous remediation.

#### Fixed
- **Portal Visual Styling & Badges (`docs/style.css`)**:
  - Resolved missing `.risk-*` and `.advisory-*` CSS class definitions ensuring risk tiers render with proper themed backgrounds and borders.
  - Eliminated redundant `display_name === package_name` duplicated headers across 100% of directory cards.
  - Suppressed empty `.server-tools-row` spacing via CSS `:empty`.
  - Suppressed duplicate `🔴 Vulnerable` badge on updates cards when `🔴 New Security Vulnerability` badge is present.
- **Runtime Async Execution (`docs/updates.js`)**:
  - Converted `init()` to `async` and cleaned up conflict syntax, resolving browser script parse failures.

---

## [1.1.3] - 2026-10-24

### 📦 Automated Catalog & Advisory Sync
- Automated daily sync and security advisory updates.

---

## [1.1.2] - 2026-10-24

### 📦 Release Engineering & Comprehensive Documentation Integration

- **Version Bump**: Bumped package version to `1.1.2`.
- **Master Audit Integration**: Linked `docs/audit/CUMULATIVE_TECHNICAL_AUDIT_REPORT.md` and `docs/audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md` into repository documentation, index, and release notes.
- **Specification & Implementation Architecture**: Updated `docs/SPECIFICATION.md` and `docs/IMPLEMENTATION.md` with sections detailing universal multi-client parsing/redaction, runtime supply-chain tamper probers, empirical invariant test suites, and DAG workflow pipelines.
- **Version-Separated Correlation Guide**: Authored `docs/version_correlation.md` specifying SemVer range matching algorithms and per-version advisory isolation.
- **Verification Guarantee**: Validated 100% test pass rate across all 346 tests.

---

## [1.1.1] - 2026-10-24

### 🛡️ Waves 11–13: Full-System Empirical Audit, Competitive Benchmarking & Cumulative Syntheses

This release publishes the comprehensive empirical live-run audit across all 8 core subsystems, completes competitive benchmarking against 10 industry solutions, and delivers the 2 master cumulative synthesis reports.

#### Added
- **Full Empirical Audit Test Suite** (`tests/audit/`):
  - 28 dedicated empirical invariant tests (`test_audit_task59.py` through `test_audit_task66.py`) evaluating 26 core invariants across live environments.
  - Overall test suite expanded to **346 passed, 5 skipped (100% pass rate)**.
- **Cumulative Master Deliverables**:
  - `docs/audit/CUMULATIVE_TECHNICAL_AUDIT_REPORT.md`: Comprehensive synthesis of all 8 empirical subsystem audits; 26 invariants matrix; 15 resolved defects (8 HIGH, 5 MEDIUM, 2 LOW); subsystem scorecards (100% post-patch).
  - `docs/audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md`: Grand Unified Competitive Feature Matrix across 10 industry solutions (Verity, Anthropic, Cursor, Smithery, Glama, Snyk, Semgrep, Trivy, OSV, Sigstore); strategic gap register; v1.2–v2.0 architecture blueprints.
- **Competitive Benchmark Reports**:
  - `docs/audit/competitive_verity_anthropic_runtime.md`: Runtime tool interception, AST database query guarding, and inline MCP reverse proxy architecture.
  - `docs/audit/competitive_smithery_glama_registries.md`: Cloud container sandboxing, uptime health telemetry, and composite Server Trust Score formula (`mcp_trust_score`).
  - `docs/audit/competitive_snyk_semgrep_trivy_osv.md`: Interprocedural call-graph reachability analysis, typosquatting & LLM hallucinated package detection, automated PR bot blueprint.
  - `docs/audit/competitive_supply_chain_sbom.md`: Sigstore keyless Cosign signing, SLSA Level 3 build provenance, CycloneDX v1.6 AI BOM mapping, OpenSSF Scorecards API integration.
- **Interactive Terminal Hub Automation**:
  - Added `--json` and `--batch` flags to `mcp-vuln hub` for seamless non-interactive CI/CD execution.
  - Added ANSI escape sequence scrubbing (`sanitize_ansi`) preventing terminal injection (CWE-150).
  - Added SIGINT trap restoring terminal cursor visibility and alternate buffer state.

#### Fixed
- **Ingestion Deduplication**: Fixed range duplication in `OsvDeduplicator._merge_affected()` to collapse redundant open ranges when merging cross-source advisories.
- **Multi-Client Config Parsing**: Added UTF-8 BOM stripping, URL-safe comment stripping, trailing comma tolerance, Windows path normalization, and automated secret token redaction (`***REDACTED***`).
- **Supply Chain Tamper Engine**: Elevated unadvertised shadow tool injection to `CRITICAL` severity with dedicated OWASP MCP SARIF rules (`MCP002`); added description drift tracking (`MCP001`).
- **Behavioral Prober Transport**: Progressive stdout noise filtering in `StdioTransport` discarding initialization debug logs until valid JSON-RPC frames arrive; added child process zombie cleanup.
- **Auto-Fixer Atomicity**: Enforced atomic backup creation (`<config>.bak.<timestamp>`) and atomic writes via tempfile with automated rollback on write failure; enforced monotonic SemVer upgrade targets.
- **Multicore Site Builder**: Enforced `sort_keys=True` in all JSON outputs for bit-for-bit SHA-256 byte determinism across worker counts; caught `BaseException` in process pool future aggregator to isolate worker deaths and log diagnostics to `build_errors.json`.
- **Static Security Portal UI**: Added inline "Retry Fetch" button upon lazy shard network failures (404/500/offline); verified complete DOM XSS immunity via `escapeHtml()`.

---

## [1.1.0] - 2026-10-24

### 🚀 Wave 10: Next-Gen AI Runtime Security & Fingerprint Synergy

This major release introduces universal 9-client auditing, zero-day supply-chain tampering and shadow tool detection, dynamic stdio/SSE behavioral topology server identification, multi-ecosystem polyglot vulnerability correlation, an interactive security command terminal hub, and high-performance multi-core parallel site building.

#### Added
- **Universal 9-AI-Client Auditing & Global Package Discovery** (`mcp-vuln audit`):
  - Automatically audits configurations across 9 AI clients: Claude Desktop, Cursor, VS Code, Zed (`context_servers`), Cline, Windsurf, Continue, LibreChat, and OpenWebUI.
  - Automatically discovers and audits globally installed MCP tools (`npm -g` and `npx` cache).
  - New CLI flags: `--all-clients`, `--client <name>`, `--global`, `--custom-config <path>`.
- **Zero-Day Supply-Chain Tamper & Shadow Tool Drift Detection** (`mcp-vuln audit --verify-signatures`):
  - Dynamic canonical hashing (`toolset_canonical_hash`) comparing live runtime tools and parameters against baseline passport signatures.
  - Flags unadvertised/injected shadow tools (`MCP002`) and schema parameter tampering (`MCP001`) with SARIF v2.1.0 annotations.
  - Added `--strict-integrity` flag to enforce zero drift tolerance.
- **Dynamic Behavioral Topology Prober & Server Identification** (`mcp-vuln identify`):
  - Probes unlabelled, custom, or wrapped MCP server processes over stdio and SSE.
  - Calculates topological Jaccard similarity across 5,533 server passports to identify the true underlying package and unmask hidden CVEs.
- **Polyglot Vulnerability Correlation Engine**:
  - Expanded coverage across Rust (`crates.io` / `RUSTSEC`), Go (`GO-*`), Java/Kotlin (Maven / `GHSA-java`), and zero-pull Docker Hub container image CVE feeds.
  - Emits native package manager remediation upgrade commands (`cargo update`, `go get`, `mvn versions:use-latest-releases`, `docker pull`).
- **Multi-Client Config Auto-Fixer & Interactive Security Hub** (`mcp-vuln hub`, `mcp-vuln fix`):
  - `mcp-vuln hub`: Interactive emoji-driven terminal console for 1-click universal audits, supply-chain verification, interactive CVE timelines, and side-by-side config remediation diff previews.
  - `mcp-vuln fix`: Automated remediation across all 9 clients rewriting native formats with atomic timestamped backups (`<config>.bak.<timestamp>`) and `--dry-run` unified diff previews.
- **Web Security Explorer UI Parity** (`docs/`):
  - Interactive expandable tool chips (`+N more` / `Show less ▴`) with inline DOM expansion and keyboard accessibility (`Enter`/`Space`).
  - Styled `.no-tools-badge` for zero-tool servers eliminating visual card body voids.
  - Added `#filterToolsOnly` multi-facet filter checkbox to filter out pure gateways.
- **High-Performance Multi-Core Parallel Site Builder** (`mcp-vuln site-build`):
  - Two-tier content-addressable SHA-256 cache (`TwoTierVulnerabilityCache`): Tier 1 in-memory LRU + Tier 2 SHA-256 disk cache keyed by `(passport_canonical_hash, osv_index_hash)`.
  - Multi-process parallel batch chunking (`ProcessPoolExecutor`) across CPU cores (`--workers`) with bit-for-bit determinism and sort order parity across all 32 shard files.
- **PyPI Release Publishing & Upstream Cross-Repo Dispatch Pipeline**:
  - Ingests `mcp-fingerprints>=1.0.17` with multi-tier snapshot loading (`~/.cache/mcp-fingerprints/passports.json.gz`).
  - Gated reactive cross-repo GitHub Actions workflow (`cross_repo_sync.yml`) triggered by `upstream_fingerprints_updated` events.

#### Changed
- Consolidated structural fingerprint models to import directly from `mcp_fingerprints.models` (`ServerPackageSpec`, `VersionFingerprint`, `ToolContractSignature`), eliminating redundant definitions.
- Optimized test runner suite to 323 test cases (318 passing, 5 skipped) with complete acceptance invariant coverage.

---

## [1.0.10] - 2026-10-24
### Changed
- Monotonic sync state preservation and periodic OSV vulnerability refresh.

## [1.0.7] - 2026-10-17
### Added
- GitHub Pages live portal feed and multi-version remediation switcher.

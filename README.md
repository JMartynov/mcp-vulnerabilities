# Open-Source MCP Vulnerability Advisory Database

[![Daily MCP Vulnerability Ingestion & Sync](https://github.com/JMartynov/mcp-vulnerabilities/actions/workflows/daily_sync.yml/badge.svg)](https://github.com/JMartynov/mcp-vulnerabilities/actions/workflows/daily_sync.yml)
[![Advisories Count](https://img.shields.io/badge/advisories-500%2B-red.svg)](data/vulnerabilities)
[![OSV Schema 1.6.0](https://img.shields.io/badge/schema-OSV%201.6.0-blue.svg)](https://ossf.github.io/osv-schema/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security Explorer](https://img.shields.io/badge/Security_Explorer-Live_Portal-38bdf8?style=flat-square&logo=googlechrome)](https://jmartynov.github.io/mcp-vulnerabilities/)
[![Release Updates](https://img.shields.io/badge/Release_Updates-Live_Feed-10b981?style=flat-square&logo=rss)](https://jmartynov.github.io/mcp-vulnerabilities/updates.html)

An open-source, automated **Open Source Vulnerability (OSV 1.6)** compliant security advisory database specifically curated for the **Model Context Protocol (MCP)** ecosystem.

## Sources
- **CVE List v5**: Official CVE JSON 5.0 records.
- **GitHub Security Advisories (GHSA)**: Live GraphQL/REST security alerts.
- **OSV.dev**: Unified open-source vulnerability database.
- **National Vulnerability Database (NVD)**: CVE 2.0 vulnerability metrics and CVSS scores.

## Snapshot Downloads & Mirrors

You can download pre-compiled vulnerability database snapshots, OSV buckets, and air-gapped enterprise bundles directly from our latest GitHub Release.

Download the latest consolidated JSON snapshot:
```bash
curl -sL https://github.com/JMartynov/mcp-vulnerabilities/releases/latest/download/vulnerabilities.json.gz -o vulnerabilities.json.gz
```

Verify integrity using the provided SHA-256 checksums:
```bash
curl -sL https://github.com/JMartynov/mcp-vulnerabilities/releases/latest/download/SHA256SUMS.txt -o SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt --ignore-missing
```

## Fast Consumption

You can fetch the complete vulnerability database snapshot in a single GET request:
```bash
curl -sL https://raw.githubusercontent.com/JMartynov/mcp-vulnerabilities/main/vulnerabilities.json.gz | gzip -d > vulnerabilities.json
```

### Python
```python
import gzip, json, urllib.request

url = "https://raw.githubusercontent.com/JMartynov/mcp-vulnerabilities/main/vulnerabilities.json.gz"
with urllib.request.urlopen(url) as resp:
    with gzip.GzipFile(fileobj=resp) as gz:
        data = json.load(gz)

print(f"Loaded {data['total_vulnerabilities']} MCP security advisories.")
```

## CI/CD Integration

You can easily prevent vulnerable MCP server dependencies from entering your production environment or being configured into AI client settings by adding this official, reusable GitHub Action to your CI workflows.

### Audit AI Client Configurations
```yaml
- name: Audit MCP Servers
  uses: JMartynov/mcp-vulnerabilities@v1
  with:
    config-path: ".claude/claude_desktop_config.json"
    fail-on-severity: "HIGH"
```

### Audit Dependency Manifests
```yaml
- name: Audit Transitive Dependencies
  uses: JMartynov/mcp-vulnerabilities@v1
  with:
    manifest-path: "package.json"
    fail-on-severity: "HIGH"
```

## CLI Usage

The `mcp-vulnerabilities` toolkit provides comprehensive commands for scanning client environments, probing unknown servers, running interactive remediation hubs, and building static web portals:

```bash
# 1. Interactive Terminal CLI GUI Hub (Zero-arg launch or explicit subcommand)
# Launches emoji-anchored interactive dashboard with real-time status telemetry
mcp-vuln
mcp-vuln hub
# Headless batch / JSON automation mode:
mcp-vuln hub --json

# 2. Universal 17-Client Local AI Discovery & Supply Chain Tamper Check
# Scans Claude Desktop, Claude Code, Cursor, Windsurf, Zed, Cline, Roo Code, Goose,
# Continue, JetBrains Junie, VS Code, Antigravity, OpenHands, Trae, LM Studio,
# LibreChat, and OpenWebUI + global npm/npx cache with automatic token redaction (***REDACTED***)
mcp-vuln audit --all-clients --verify-signatures

# 3. Network & Port MCP Scanner (Concurrent TCP & JSON-RPC 2.0 Handshake)
# Probes candidate paths (/, /sse, /mcp, /v1/mcp) across ports or CIDR subnets
mcp-vuln network-scan --target localhost --ports 3000-8800
mcp-vuln network-scan --cidr 192.168.1.0/24 --concurrency 64
# Unified local and network audit:
mcp-vuln audit --network --network-ports 3000,8000,8080

# 4. Stateful Security Picture & Comparative Drift Tracking
# Snapshot point-in-time security picture posture:
mcp-vuln audit --save-picture ~/.mcp-vuln/state/security_picture.json
# Snapshot approved inventory baseline:
mcp-vuln audit --save-baseline baseline.json
# Compare live scan against baseline picture and fail CI pipeline on drift (exit code 2):
mcp-vuln audit --compare-picture ~/.mcp-vuln/state/security_picture.json --fail-on-drift
mcp-vuln audit --diff baseline.json --fail-on-drift

# 5. Typosquatting & LLM Hallucinated Package Detector
# Analyzes configurations using Damerau-Levenshtein distance and homoglyph matching
mcp-vuln audit-typosquat --config .claude/claude_desktop_config.json --fix

# 6. Sigstore Keyless Attestation & Feed Verification
# Verifies the cryptographic integrity of vulnerability feeds via OIDC signatures
mcp-vuln verify-feed --feed docs/data/vulnerabilities.json.gz

# 7. Automated GitHub PR Remediation Bot
# Discovers client configs, computes safe versions, and idempotently creates PRs
mcp-vuln remediate-pr --repo-dir ./ --auto-merge

# 8. Dynamic Behavioral Server Identification & Handshake Probing
# Probes custom or wrapped server processes over stdio / SSE to uncover hidden CVEs
mcp-vuln identify --stdio "node /path/to/server.js"

# 9. Multi-Client Configuration Auto-Fixer
# Upgrades vulnerable configurations with atomic backups (<config>.bak.<timestamp>)
mcp-vuln fix --client claude --dry-run
mcp-vuln fix --all-clients

# 10. Ingest latest advisories from live APIs
mcp-vuln sync --live-api

# 11. Validate OSV 1.6 schema compliance
mcp-vuln validate --dir data/vulnerabilities

# 12. High-Performance Multicore Parallel Site Builder (Bit-for-bit SHA-256 deterministic)
mcp-vuln build-site --workers 8 --output-dir docs/data

# 13. Inline MCP Reverse Proxy Interceptor (Runtime Firewall)
# Intercepts stdio JSON-RPC to block vulnerable/shadow tools and redact secrets
mcp-vuln proxy --package <pkg> --version <v> --block-severity HIGH --redact-secrets --audit-log proxy_log.jsonl -- npx @modelcontextprotocol/server-postgres

# 14. AST Interprocedural Call-Graph Reachability Engine
# Analyzes multi-hop call graphs from MCP tool entrypoints to flag vulnerable dependencies
mcp-vuln audit-transitive --source-dir ./src --reachable-only
```

### Interactive Terminal Command Hub (`mcp-vuln` / `mcp-vuln hub`)

Launching `mcp-vuln` with zero arguments or running `mcp-vuln hub` opens an interactive, emoji-anchored terminal control center featuring real-time telemetry and categorized workflow menus:

```text
================================================================================
                     🛡️  MCP SECURITY COMMAND HUB  🛡️
================================================================================
 OS: macOS 15.3 (arm64)
 Local Clients Scanned: 14 / 17 detected
 Network Hosts Probed: localhost (12 ports active)
 Total Discovered Servers: 28 (22 Local Stdio, 6 Network SSE/HTTP)
 Baseline Picture Status: Saved (2026-10-31 10:00:15)
 Security Posture: ⚠️ WARNING (2 High CVEs, 1 Shadow Server)
================================================================================

  [1] 🖥️  Local Workstation Audit & Shadow MCP Discovery
  [2] 🌐 Network & Port MCP Scanner
  [3] 📸 Baseline Picture & Security Drift Analysis
  [4] 🛡️  Vulnerability Audit, Fingerprinting & Remediation
  [5] 📦 Export Reports & Compliance (SARIF / CycloneDX / JSON)
  [0] 🚪 Exit

================================================================================
```

## Production Readiness Audit & Competitive Intelligence

`mcp-vulnerabilities` has undergone an autonomous, empirical live-run audit across all 8 core subsystems, evaluating 26 invariants with zero regressions, and benchmarking against 10 industry standards:

| Master Audit Deliverable | Strategic Purpose & Contents | Link |
| :--- | :--- | :---: |
| **Cumulative Technical Audit Report** | Synthesis of all 8 empirical audits (Tasks 59–66); 26/26 invariants verified; 15 cataloged & resolved defects (8 HIGH, 5 MEDIUM, 2 LOW); subsystem health scorecards. | [**`CUMULATIVE_TECHNICAL_AUDIT_REPORT.md`**](docs/audit/CUMULATIVE_TECHNICAL_AUDIT_REPORT.md) |
| **Cumulative Competitive Gap Analysis & Roadmap** | Grand Unified Feature Matrix across 10 products (Verity, Anthropic, Cursor, Smithery, Glama, Snyk, Semgrep, Trivy, OSV, Sigstore); strategic gap register; v1.2–v2.0 architecture blueprints (Reverse Proxy, AST Reachability, Keyless Signatures). | [**`CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md`**](docs/audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md) |
| **Wave 14 Portal & Analytics Code Review** | Comprehensive verification & line-by-line code review of Tasks 73–77; evaluation of visual styling, cryptographic fingerprints, zero-day gap analytics, historical sparklines, and in-browser config auditor dropzone. | [**`code_review_wave14_portal_and_analytics.md`**](docs/reports/code_review_wave14_portal_and_analytics.md) |

### Detailed Subsystem Audit Reports
- [**Task 59: Ingestion & Monotonic Stream Audit**](docs/audit/audit_task59_ingestion_and_schema.md): OSV 1.6 range integrity, deduplicator range collapsing fix, mid-batch recovery.
- [**Task 60: Universal 9-Client Discovery Audit**](docs/audit/audit_task60_universal_9client_discovery.md): Permissive JSONC/JSON5 parsing, UTF-8 BOM stripping, symlink recursion guard, secret token redaction (`***REDACTED***`).
- [**Task 61: Supply Chain Tamper & Shadow Drift Audit**](docs/audit/audit_task61_supply_chain_tamper.md): Zero-day tool mutation detection, unadvertised shadow tool injection alerts (`CRITICAL`), docstring prompt injection tracking.
- [**Task 62: Behavioral Topology Prober Audit**](docs/audit/audit_task62_behavioral_topology_prober.md): STDIO stdout noise filtering, socket disconnect resilience, child process zombie cleanup.
- [**Task 63: Polyglot Correlator & Multi-Client Fixer Audit**](docs/audit/audit_task63_polyglot_and_fixer.md): In-place native schema preservation, atomic backup creation, write failure rollback, monotonic SemVer upgrade targets.
- [**Task 64: Interactive Terminal Hub Robustness Audit**](docs/audit/audit_task64_interactive_hub_robustness.md): Headless/non-TTY fallback, unified diff dry-runs, SIGINT terminal restoration, ANSI escape sequence scrubbing (CWE-150).
- [**Task 65: Multicore Site Builder & Cache Audit**](docs/audit/audit_task65_site_builder_cache.md): Bit-for-bit SHA-256 byte equality across worker counts (`workers=1` vs `workers=8`), non-fatal worker crash isolation, content-addressed cache invalidation.
- [**Task 66: Static Web Security Portal UI Parity Audit**](docs/audit/audit_task66_web_portal_ui_parity.md): "Only Servers with Tools" filter parity, zero-tool badge rendering, DOM XSS immunity, shard fetch network failure inline retry.

### Competitive Ecosystem Benchmarks
- [**Task 67: Verity & Anthropic Runtime Benchmark**](docs/audit/competitive_verity_anthropic_runtime.md): Verity DB Guard/Oracle, Anthropic Inspector SDK, Cursor Sandbox; inline reverse proxy architecture design.
- [**Task 68: Smithery & Glama Registry Security Models**](docs/audit/competitive_smithery_glama_registries.md): Automated build sandboxing, dynamic health telemetry, composite Server Trust Score formula (`mcp_trust_score`).
- [**Task 69: Snyk, Semgrep, Trivy & OSV-Scanner SCA Engines**](docs/audit/competitive_snyk_semgrep_trivy_osv.md): Interprocedural call-graph reachability, typosquatting & LLM hallucinated package detection, automated PR bot blueprint.
- [**Task 70: Supply Chain Attestation & CycloneDX AIBOM**](docs/audit/competitive_supply_chain_sbom.md): Sigstore keyless Cosign signing, SLSA Level 3 build provenance, CycloneDX v1.6 AI BOM mapping, OpenSSF Scorecards API integration.

## Migrated Security Mechanisms & Tooling Suite

`mcp-vulnerabilities` is the authoritative home for Model Context Protocol security analysis, vulnerability intelligence, and advisory correlation. All security-specific mechanisms migrated from `mcp-fingerprints` are unified here:

* **Concurrent Network & Port MCP Scanner (`mcp_vulnerabilities.probe.network_scanner`)**: Asynchronous TCP port pre-check and JSON-RPC 2.0 handshake (`initialize`, `tools/list`, `prompts/list`, `resources/list`) across candidate paths (`/`, `/sse`, `/mcp`, `/v1/mcp`) supporting host targets, port ranges, and CIDR blocks (`192.168.1.0/24`).
* **Universal 17-Client Local AI Discovery Engine (`mcp_vulnerabilities.audit.parsers`)**: Deep discovery and permissive JSONC parsing across 17 AI clients (Claude Desktop, Claude Code CLI, Cursor, Windsurf, Zed, Cline, Roo Code, Goose, Continue, JetBrains Junie, VS Code / Copilot, Antigravity, OpenHands, Trae, LM Studio, LibreChat, OpenWebUI) + global npm/npx cache with automated secret token redaction (`***REDACTED***`).
* **Stateful Security Picture & Comparative Drift Engine (`mcp_vulnerabilities.audit.picture`, `picture_diff`, `drift`)**: Captures point-in-time posture snapshots (`~/.mcp-vuln/state/security_picture.json` or custom baseline) and tracks fine-grained drift across newly introduced CVEs, resolved vulnerabilities, supply chain tamper incidents, new high-risk tools, and shadow servers.
* **Interactive Terminal CLI GUI Hub (`mcp_vulnerabilities.audit.hub`)**: Zero-argument launch (`mcp-vuln`) or `mcp-vuln hub` presenting an emoji-anchored interactive dashboard with status header telemetry, 6-category workflow menus, and ANSI-safe fallback.
* **Cross-Repository Passport Correlation (`mcp_vulnerabilities.sync_manager`)**: Ingests `passports.json.gz` from `mcp-fingerprints` to map OSV advisories directly against 5,000+ structural server passports and tool contract signatures.
* **Multi-Engine Heuristic Threat Analyzer (`mcp_vulnerabilities.analyzer`)**: Scans MCP servers for unsafe execution patterns, command injection vectors, and missing parameter bounds.
* **Protocol & Contract Linter**: Validates MCP tool definitions against protocol standards, schema invariants, and capability risk classifications.
* **Headless REST API Daemon (`mcp-vuln serve`)**: Microservice daemon providing JSON endpoints for CI/CD gates, local scanners, and AI client configuration verifiers.
* **Inline MCP Reverse Proxy Interceptor (`mcp_vulnerabilities.proxy`)**: Runtime bidirectional JSON-RPC firewall that intercepts `tools/list` and `tools/call`, blocking OSV `vulnerable_tools` and shadow tools with JSON-RPC error code `-32001`, and redacting secrets from responses.
* **AST Interprocedural Call-Graph Reachability Engine (`mcp_vulnerabilities.analyzers.reachability`)**: Traces multi-hop call graphs from `@mcp.tool()` / `server.tool()` entrypoints to flag third-party dependencies as `REACHABLE_FROM_TOOL`, `IMPORTED_ONLY`, or `UNREACHABLE`.

## Version-Separated Vulnerability Tracking

Unlike generic package databases, `mcp-vulnerabilities` maintains version-separated vulnerability tracking tailored to the MCP ecosystem:
* **Per-Version Isolation**: Clearly differentiates between vulnerable releases (e.g., `v1.0.0`) and patched safe releases (e.g., `v1.1.0`), preventing false positive alerts on updated installations.
* **Discrete Advisory Matrices**: Links specific CVEs, GHSAs, and OWASP MCP categories to the exact tool signatures and endpoints affected.
* **Automated Safe Version Recommendation**: Identifies the minimum recommended non-vulnerable version and generates 1-click pinned client configurations for **Claude Desktop**, **Cursor**, **Cline**, **Zed**, and **Windsurf**.

## Web Explorer, Live Updates & Enhanced Analytics Portals

The project provides interactive, client-side static web portals hosted directly from GitHub Pages:

* **[Unified MCP Security Explorer (`docs/index.html`)](https://jmartynov.github.io/mcp-vulnerabilities/)**:
  - **Directory Infinite Scroll & DOM Virtualization**: Sentinel-based `IntersectionObserver` progressive batching (48 cards/chunk) rendering all 6,280+ indexed MCP servers at 60 FPS without layout jank or memory leaks.
  - **Multi-Server Safe Config Basket & Floating Bottom Drawer**: Persistent selection basket across searches with slide-up floating drawer and 6-client unified JSON exporter (**Claude Desktop**, **Cursor**, **Zed**, **Windsurf**, **Cline**, **Continue**).
  - **Web Cross-Server Tool Collision Warnings**: Real-time safety detector analyzing selected basket servers to flag identical tool names (`tools/list` collision) before configuration export, mitigating runtime tool shadowing and prompt hijacking.
  - **In-Card Tool Drawer with Real-Time Microsearch**: Expandable inline tool drawer embedded within directory cards with instant keyword microsearch and live match counters across server tools.
  - **AST Protocol Behavior Badges**: Color-coded badges rendering static capability invariants (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) extracted directly from server passports.
  - **PWA Offline Support & Cache-First Routing**: Progressive Web App manifest (`docs/manifest.json`) and service worker (`docs/sw.js`) enabling zero-network offline discovery and cached advisory navigation.
  - **Card Footer Quick Client Copy & In-Modal Search**: 1-click client configuration copy buttons in card footers, plus interactive in-modal search input for servers with 40+ tools.
  - **Directory Explorer**: Multi-criteria sorting (Risk, Advisories, Tools, A-Z), bidirectional URL deep-linking (`?q=`, `?server=`, `?tab=`), and composite risk tiers.
  - **MCP Primitives & Passports**: Surfaces live counts for `🔧 Tools`, `📄 Prompts`, and `📦 Resources`, transport tags (`🖥️ Local Stdio`), and required environment variables.
  - **Interactive Server Modal**: Version switcher, arbitrary two-version diff comparator computing tool mutations/CVE deltas, and 4th sub-tab "🌐 Endpoints & Schema" mapping live deployment URLs and plaintext warnings.
  - **🛡️ Audit My MCP Setup (Tab 3)**: In-browser client config dropzone featuring 1-click sample presets, "Download Fixed Config (.json)", and "Export Markdown Audit Report (.md)" exporters.

* **[Release Updates & Advisory Delta Feed (`docs/updates.html`)](https://jmartynov.github.io/mcp-vulnerabilities/updates.html)**:
  - **Historical Release Selector**: Timeline dropdown covering historical sync releases (v1.2.0 through v1.0.0).
  - **Velocity Sparkline**: Dual-series responsive SVG trend chart tracking server growth and advisory volume over the past 10 releases.
  - **Dynamic Change-Type Filter Chips**: Instant filtering across *All Updates*, *🟢 Patched Versions Available*, *🔴 New Security Vulnerabilities*, and *🆕 Newly Tracked Servers* with live count indicators.
  - **Toolset Evolution**: Side-by-side delta visualization tracking added (`+`) and removed (`-`) tools, parameter changes, and SHA-256 fingerprint transitions (`sha256:old... ➔ sha256:new...`).
  - **Syndication Feeds**: One-click subscription via [Atom Feed (`docs/data/feed.atom`)](https://jmartynov.github.io/mcp-vulnerabilities/data/feed.atom) and [JSON Feed (`docs/data/feed.json`)](https://jmartynov.github.io/mcp-vulnerabilities/data/feed.json).

* **[Multi-Dimensional Analytics Dashboard (`docs/analytics.html`)](https://jmartynov.github.io/mcp-vulnerabilities/analytics.html)**:
  - **Interactive Click-to-Filter Drilldowns**: Clickable tool chips, OWASP category tiles, and zero-day gap cards navigating directly to `index.html` with active filter parameters.
  - **Zero-Day & Remediation Gap**: Quantifies patched vs. unpatched vulnerable servers (32.0% safe patches vs. 68.0% active zero-days with no upstream fix).
  - **Static Capability Surface**: Aggregates high-risk permissions across the catalog, including Filesystem Access, Shell/Process Execution, and Network Egress.

## Automated PyPI Release Pipeline on Data Updates

`mcp-vulnerabilities` is dependent on two distinct upstream data sources:
1. External OSV/NVD/CVE security advisories (stored in `data/vulnerabilities/`)
2. Upstream MCP server fingerprints and tool schemas from `mcp-fingerprints` (`data/passports.json.gz`)

To keep downstream tools, scanners, and Python consumers immediately updated with zero human intervention:
1. **Triggers (`.github/workflows/daily_sync.yml`)**: Executes daily at 03:00 UTC. It is also triggered reactively via a `repository_dispatch` event (`upstream_fingerprints_updated`) whenever `mcp-fingerprints` publishes a new release.
2. **Cross-Repo Sync**: Automatically pulls the latest `passports.json.gz` release asset from `mcp-fingerprints` (with a raw fallback mechanism in case of missing asset or rate limits).
3. **Substantive Change Detection (`VULN_CHANGES`)**: Assesses whether new security advisories, catalog updates, or passport changes (`data/passports.json.gz`) occurred.
4. **Automated Semantic Version Bump**: Runs `scripts/bump_version.py --apply` to increment the patch version.
5. **Static Artifact Recompilation**: Rebuilds `docs/data/` catalog shards, advisory indexes, and release delta feeds via `site_builder` and `updates_builder`.
6. **Automated PyPI Publishing**: Tags the commit (`vX.Y.Z`), creates an official GitHub Release with generated release notes, and invokes `./.github/workflows/release.yaml` to publish the updated wheel to PyPI via OIDC Trusted Publishing.

## Documentation

- [Specification](docs/SPECIFICATION.md): Details the OSV 1.6 schema extensions, semantics, and vulnerability invariants.
- [Cross-Repo Architecture](docs/cross_repo_architecture.md): Blueprint for structural passport ingestion and correlation workflows.
- [Implementation](docs/IMPLEMENTATION.md): Architecture blueprint covering ingestion pipelines, state machines, and acceptance tests.

## Testing & Verification

The test suite enforces 100% runnable pass rates across both regression suites and empirical invariant audits:

```bash
# Run the entire test suite (400+ passed tests)
pytest -q

# Run the empirical subsystem invariant audit suite
pytest -q tests/audit/

# Run acceptance tests
pytest -q tests/test_acceptance_*.py
```

## License
MIT


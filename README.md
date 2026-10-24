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
# 1. Universal 9-Client Security Audit & Supply Chain Tamper Check
# Scans Claude Desktop, Cursor, Zed, Windsurf, Cline, Continue, Roo Code, LibreChat, and OpenWebUI
mcp-vuln audit --all-clients --verify-signatures

# 2. Interactive Terminal Security Hub (with unified diff preview & non-TTY fallback)
mcp-vuln hub
# Headless batch / JSON automation mode:
mcp-vuln hub --json

# 3. Dynamic Behavioral Server Identification & Handshake Probing
# Probes custom or wrapped server processes over stdio / SSE to uncover hidden CVEs
mcp-vuln identify --stdio "node /path/to/server.js"

# 4. Multi-Client Configuration Auto-Fixer
# Upgrades vulnerable configurations with atomic backups (<config>.bak.<timestamp>)
mcp-vuln fix --client claude --dry-run
mcp-vuln fix --all-clients

# 5. Ingest latest advisories from live APIs
mcp-vuln sync --live-api

# 6. Validate OSV 1.6 schema compliance
mcp-vuln validate --dir data/vulnerabilities

# 7. High-Performance Multicore Parallel Site Builder (Bit-for-bit SHA-256 deterministic)
mcp-vuln build-site --workers 8 --output-dir docs/data
```

## Production Readiness Audit & Competitive Intelligence

`mcp-vulnerabilities` has undergone an autonomous, empirical live-run audit across all 8 core subsystems, evaluating 26 invariants with zero regressions, and benchmarking against 10 industry standards:

| Master Audit Deliverable | Strategic Purpose & Contents | Link |
| :--- | :--- | :---: |
| **Cumulative Technical Audit Report** | Synthesis of all 8 empirical audits (Tasks 59–66); 26/26 invariants verified; 15 cataloged & resolved defects (8 HIGH, 5 MEDIUM, 2 LOW); subsystem health scorecards. | [**`CUMULATIVE_TECHNICAL_AUDIT_REPORT.md`**](docs/audit/CUMULATIVE_TECHNICAL_AUDIT_REPORT.md) |
| **Cumulative Competitive Gap Analysis & Roadmap** | Grand Unified Feature Matrix across 10 products (Verity, Anthropic, Cursor, Smithery, Glama, Snyk, Semgrep, Trivy, OSV, Sigstore); strategic gap register; v1.2–v2.0 architecture blueprints (Reverse Proxy, AST Reachability, Keyless Signatures). | [**`CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md`**](docs/audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md) |

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

* **Cross-Repository Passport Correlation (`mcp_vulnerabilities.sync_manager`)**: Ingests `passports.json.gz` from `mcp-fingerprints` to map OSV advisories directly against 5,000+ structural server passports and tool contract signatures.
* **Multi-Engine Heuristic Threat Analyzer (`mcp_vulnerabilities.analyzer`)**: Scans MCP servers for unsafe execution patterns, command injection vectors, and missing parameter bounds.
* **Protocol & Contract Linter**: Validates MCP tool definitions against protocol standards, schema invariants, and capability risk classifications.
* **Headless REST API Daemon (`mcp-vuln serve`)**: Microservice daemon providing JSON endpoints for CI/CD gates, local scanners, and AI client configuration verifiers.

## Version-Separated Vulnerability Tracking

Unlike generic package databases, `mcp-vulnerabilities` maintains version-separated vulnerability tracking tailored to the MCP ecosystem:
* **Per-Version Isolation**: Clearly differentiates between vulnerable releases (e.g., `v1.0.0`) and patched safe releases (e.g., `v1.1.0`), preventing false positive alerts on updated installations.
* **Discrete Advisory Matrices**: Links specific CVEs, GHSAs, and OWASP MCP categories to the exact tool signatures and endpoints affected.
* **Automated Safe Version Recommendation**: Identifies the minimum recommended non-vulnerable version and generates 1-click pinned client configurations for **Claude Desktop**, **Cursor**, **Cline**, **Zed**, and **Windsurf**.

## Web Explorer & Live Updates Portals

The project provides interactive, client-side static web portals hosted directly from GitHub Pages:

* **[Unified MCP Security Explorer (`docs/index.html`)](https://jmartynov.github.io/mcp-vulnerabilities/)**:
  - **Directory Tab**: Search and filter 5,000+ indexed MCP servers with capability risk badges, version status indicators, and tool previews.
  - **Advisories Tab**: Full-text search across all published OSV/CVE advisories with severity filters (CRITICAL, HIGH, MEDIUM, LOW) and OWASP MCP categories.
  - **Deep-Dive Server Inspector**: Interactive version switcher, tool parameter schema tables (`Name`, `Type`, `Required`, `Default`, `Enum`, `Description`), security commentary, and 1-click configuration exporters.
* **[Release Updates & Advisory Delta Feed (`docs/updates.html`)](https://jmartynov.github.io/mcp-vulnerabilities/updates.html)**:
  - Real-time release timeline tracking newly published advisories and patched MCP servers per version.
  - Summary metrics: new advisories, updated servers, and patched versions.
  - Standalone JSON feed endpoints available at `docs/data/updates/latest_update.json` and `docs/data/updates/updates_history.json`.

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
# Run the entire test suite (346 passed, 5 skipped)
pytest -q

# Run the empirical subsystem invariant audit suite
pytest -q tests/audit/

# Run acceptance tests
pytest -q tests/test_acceptance_*.py
```

## License
MIT


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
```bash
# Ingest latest advisories from live APIs
python -m mcp_vulnerabilities.cli sync --live-api

# Validate OSV schema compliance
python -m mcp_vulnerabilities.cli validate --dir data/vulnerabilities

# Compile compressed snapshot
python -m mcp_vulnerabilities.cli snapshot
```

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

## Testing

Execute the acceptance test suite to validate the end-to-end functionality:

```bash
uv run pytest -v tests/test_acceptance_*.py
```

## License
MIT


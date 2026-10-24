# Changelog

All notable changes to the `mcp-vulnerabilities` project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

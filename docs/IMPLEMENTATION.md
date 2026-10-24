# Implementation Architecture

This document describes the end-to-end architecture and implementation details for the MCP Vulnerability Advisory Database.

## 1. Multi-Registry Discovery (`mcp_vulnerabilities.discovery`)

The discovery module is responsible for identifying components and packages to monitor across various ecosystems (npm, PyPI, Go, etc.). It resolves metadata from these registries to build a comprehensive list of targets for vulnerability ingestion. The module provides the functionality to resolve package versions and track potential state changes needed by the ingestion pipeline.

## 2. Multi-Source Ingestion & Normalization Pipeline (`mcp_vulnerabilities.pipeline`)

The ingestion pipeline (`mcp_vulnerabilities.pipeline`) handles the automated extraction and parsing of security advisories from various external sources:

- **CVE List V5 (CVEListV5)**: Consumes official CVE JSON 5.0 records.
- **GitHub Security Advisories (GHSA)**: Integrates with GitHub's GraphQL/REST APIs to retrieve the latest advisories.
- **OSV.dev**: Unified database fetcher for open-source vulnerability records.
- **NVD**: Enriches base vulnerability records with metrics and CVSS scores.

Advisories from these divergent sources are standardized and normalized into the unified OSV 1.6 compliant schema defined in the [Specification](SPECIFICATION.md). The pipeline is responsible for merging overlapping ranges and partitioning records logically by ecosystem and repository.

## 3. State Machines (`SyncStateManager` and `McpCatalogState`)

To orchestrate the ingestion workflow efficiently, the system utilizes state management abstractions:

- **`SyncStateManager`**: Manages the life cycle of synchronization jobs, ensuring that the pipeline performs incremental fetches using appropriate checkpoints (e.g., `since` timestamps or Git commit SHAs).
- **`McpCatalogState`**: Persists the ongoing synchronization metadata within `data/mcp_catalog_state.json`. It tracks previously observed semvers and records the checkpoint data (like `last_sync_timestamp` and `last_commit_sha`) required to perform incremental synchronization in subsequent runs.

These components ensure idempotency, prevent redundant network calls, and maintain a historical search index.

## 4. Acceptance Test Suite Guide (`tests/test_acceptance_*.py`)

The acceptance tests are designed to validate the end-to-end functionality of the vulnerability ingestion pipeline against realistic scenarios.

### Execution

To run the full acceptance test suite, invoke pytest on the targeted pattern:

```bash
uv run pytest -v tests/test_acceptance_*.py
```

### Scope

The acceptance test suite includes:
- **Repository Processing**: Tests the ability of the pipeline to discover and pull correctly from defined real repositories (`test_acceptance_real_repositories.py`).
- **Data Integrity Validation**: Ensures that OSV 1.6 formatting is applied uniformly.
- **State Preservation**: Verifies that state parameters (checkpoint timestamps and commit SHAs) are consistently updated following a successful run.

Developers are encouraged to execute this suite prior to opening PRs to guarantee the integrity of the data processing pipelines.

---

## 5. Multi-Server Tool Conflict Detection, Automated Resolver & Client Config Exporters

To mitigate tool shadowing, parameter hijacking, and prompt injection attacks in multi-server client configurations, `mcp_vulnerabilities.audit` provides:

### 5.1 Multi-Server Conflict Detector (`mcp_vulnerabilities.audit.conflict_detector`)
- **Ingestion**: Evaluates Claude Desktop (`mcpServers`), Zed (`context_servers`), Cursor, and Cline configuration files.
- **AST Matching**: Resolves configured servers against passport tool registries to index all exposed tools by canonical hash and parameter schema.
- **Collision Flagging**: Flags when multiple servers expose identical tool names, identifying whether signatures are `IDENTICAL` (same hash) or `DIVERGENT` (parameter mismatch or conflicting descriptions).
- **Risk Assessment**: Flags `has_critical_conflicts` if any colliding tool carries `critical` or `high` capability risk (e.g., arbitrary command execution or filesystem modification).

### 5.2 Automated Conflict Resolver (`mcp_vulnerabilities.audit.conflict_resolver`)
Implements automated configuration rewriting under three distinct strategies:
- `prefix`: Namespaces conflicting tools via environment variables (`MCP_PREFIX_<TOOL>=<server>__`) and server argument prefixes (`--prefix=<server>__`).
- `priority`: Preserves the tool on the preferred primary server while adding the tool to `disabledTools` on shadowing servers.
- `report`: Audits without modifying files, generating human-readable and machine-actionable collision diagnostics.

### 5.3 Client Configuration Exporters (`mcp_vulnerabilities.audit.config_exporter`)
Provides modular client configuration generation and JSONC patching for:
- **Claude Desktop** (`ClaudeExporter`, root key `mcpServers`)
- **Cursor** (`CursorExporter`, root key `mcpServers`)
- **Cline** (`ClineExporter`, root key `mcpServers`)
- **Zed** (`ZedExporter`, root key `context_servers` with `{command: {path, args}}` schema)
- **Windsurf** (`WindsurfExporter`, root key `mcpServers`)
- **Docker** (`DockerExporter`, containerized execution with `--network none`)
- Preserves user comments in existing configuration files using delimiter-safe `patch_jsonc()`.

### 5.4 SARIF v2.1.0 Collision Rules (`SarifReporter.generate_collision_sarif`)
Emits OASIS SARIF v2.1.0 reports for GitHub Code Scanning with specialized structural rules:
- `MCP-STRUCTURAL-COLLISION-CRITICAL` (`level: error`)
- `MCP-STRUCTURAL-COLLISION-HIGH` (`level: error`)
- `MCP-STRUCTURAL-COLLISION-MEDIUM` (`level: warning`)
- `MCP-STRUCTURAL-COLLISION-LOW` (`level: note`)

## 6. Version-Separated Vulnerability Correlation Engine & Unified Security Catalog

### 6.1 Vulnerability Correlation Architecture (`mcp_vulnerabilities.fingerprints.correlator`)
`VulnerabilityCorrelator` maps upstream structural server passports against OSV vulnerability advisories:
- Normalizes package names across ecosystems (`PyPI`, `npm`, `golang`, `generic`).
- Compares discrete version strings against OSV `affected[].ranges` via `VulnerabilityMatcher._is_version_in_ranges()`.
- Produces `CorrelatedTimeline` and `VersionVulnerabilityState` capturing discrete vulnerability status per version.

### 6.2 Unified MCP Security Catalog (`mcp_vulnerabilities.catalog.build_unified_mcp_security_catalog`)
`build_unified_mcp_security_catalog(passports_path, vulnerabilities_dir)` creates a unified security catalog:
- Constructs `UnifiedMcpSecurityRecord` for every passport package and synthesizes milestones for advisory-only packages.
- Strictly separates vulnerability advisories into per-version `VersionSecurityRecord.advisories` (non-affected versions have `is_vulnerable=False`).
- Computes `recommended_safe_version` identifying the latest available release without known CVEs.
- Evaluates individual tools with capability risk classifier and security commentary into `ToolSecurityAssessment`.
- Structural models support rich schemas: `ParameterMetadata`, `ResourceSignature`, `PromptSignature`, `ToolContractSignature`, `VersionFingerprint`, and `ServerPackageSpec`.

### 6.3 CLI Tooling Extensions
- `mcp-vuln timeline <server> [--target-version <v>]`: Terminal display of release security timeline.
- `mcp-vuln correlate [--output <file>]`: Batch correlation export of all passports against advisories.
- `mcp-vuln resolve-config <file> [--strategy prefix|priority|report]`: Automated client configuration collision resolver.
- `mcp-vuln export-config <package> [--client claude|cursor|cline|zed|windsurf|docker]`: Client config exporter pinned to safe versions.

## 7. Dual Upstream Data Architecture & Automated Release Pipeline

`mcp-vulnerabilities` is dependent on two distinct upstream data sources:
1. **External OSV/NVD/CVE Security Advisories**: Stored in `data/vulnerabilities/`.
2. **Upstream MCP Server Passports**: Fingerprints and tool schemas fetched from `mcp-fingerprints` (`data/passports.json.gz`).

To maintain real-time correlation and data integrity, `mcp-vulnerabilities` triggers an immediate downstream sync via `repository_dispatch` (`upstream_fingerprints_updated`) whenever `mcp-fingerprints` publishes a new release. This cross-repo workflow pulls the updated `passports.json.gz`, runs correlation against existing CVEs, bumps the release version, and publishes to PyPI automatically.

### 7.1 Automated Delta Detection (`mcp_vulnerabilities.delta_detector.DeltaDetector`)
`DeltaDetector` inspects differences between existing and incoming security advisory collections to trigger releases only when substantive changes occur:
- Detects new CVE/GHSA advisory IDs.
- Tracks modifications in affected SemVer ranges (`type`, `introduced`, `fixed`, `limit`).
- Identifies risk assessment updates (CVSS v3/v4 score adjustments).

### 7.2 Semantic Version Bumper (`scripts/bump_version.py`)
Provides standalone CLI and importable functions to bump versions cleanly:
- Supports `--dry-run`, `--apply`, and `--part patch|minor|major`.
- Synchronizes `pyproject.toml` (`version = "X.Y.Z"`) and `src/mcp_vulnerabilities/__init__.py` (`__version__ = "X.Y.Z"`).
- Default `--dry-run` calculates and outputs the next semantic version.

### 7.3 Reusable PyPI Release Workflow (`.github/workflows/release.yaml`)
Configured with `workflow_call:` trigger and `skip-existing: true` allowing invocation directly from `daily_sync.yml` upon delta confirmation:
- Standard OIDC trusted publishing to PyPI (`id-token: write`).
- Skips re-upload errors if a package version already exists.

## 8. Version-Aware Unified Static Site Builder & Sharded Datasets (`mcp_vulnerabilities.site_builder`)

### 8.1 Unified Static Data Architecture
The static site builder compiles high-performance assets for browser client consumption without requiring backend runtime servers:
- **`docs/data/mcp_catalog_index.json`**: Compact, fast-loading search index covering all 5,050+ known MCP servers. Contains server identity, ecosystem, repository links, static capability risk tier, version vulnerability counts, recommended safe version, security summary comments, tool preview samples, and shard references (`shard_id`, `shard_file`).
- **`docs/data/shards/shard_<00..1f>.json`**: 32 deterministic hex-partitioned JSON files (hashed by `sha256(ecosystem:package_name) % 32`). Each shard contains full deep-dive records (`UnifiedMcpSecurityRecord`) including discrete version histories (`versions[]`), isolated vulnerability advisories per version, toolset canonical hashes, tool capability risk scores and security comments, protocol annotations, and full parameter metadata schemas (`ParameterMetadata`).
- **`docs/data/vulnerabilities.json`**: Complete OSV-compliant database of security advisories with database-specific MCP extensions (`vulnerable_tools`, `owasp_mcp_category`, `remediation_guidance`).
- **`docs/data/analytics.json`**: Pre-aggregated metrics covering ecosystem distributions, OWASP MCP Top 10 category frequencies, risk tier totals, safe vs. vulnerable package counts, and top vulnerable tool names.

### 8.2 Execution and Testing
- Run module: `.venv/bin/python -m mcp_vulnerabilities.site_builder`
- Unit and acceptance tests: `tests/test_site_builder_unified.py`

---

## 9. Universal Multi-Client Config Discovery, Parsing & Safe Migration

The `mcp_vulnerabilities.audit` subsystem provides complete coverage across modern AI coding assistants and desktop environments to detect and remediate vulnerabilities in client configurations:

### 9.1 Multi-Client Support (9 Environments)
The discovery and parser engine automatically detects configuration files across macOS, Linux, and Windows for:
1. **Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json` (`mcpServers`)
2. **Cursor**: `~/.cursor/mcp.json` or `.cursor/mcp.json` (`mcpServers`)
3. **Zed Editor**: `~/.config/zed/settings.json` (`context_servers` with `{command: {path, args}}` schema)
4. **Cline (VS Code Extension)**: `globalStorage/saoudrizwan.claude-dev/.../cline_mcp_settings.json` (`mcpServers`)
5. **Windsurf**: `~/.codeium/windsurf/mcp_config.json` (`mcpServers`)
6. **Roo Code (VS Code Extension)**: `globalStorage/rooveterinaryinc.roo-cline/.../mcp_settings.json` (`mcpServers`)
7. **LibreChat**: `librechat.yaml` (`mcpServers`)
8. **Continue.dev**: `~/.continue/config.json` (`experimental.modelContextProtocolServers`)
9. **Amazon Q Developer**: `~/.aws/amazon-q/mcp.json` (`mcpServers`)

### 9.2 Resilient JSONC & Encoding Engine (`client_parser.py`)
- **Byte Order Mark (BOM) Stripping**: Automatically strips UTF-8, UTF-16 LE, and UTF-16 BE BOMs prior to tokenization.
- **URL-Safe Comment Stripping**: Removes `//` single-line and `/* ... */` multi-line comments without mangling URLs (e.g. `http://` or `https://`).
- **Trailing Comma & Whitespace Tolerance**: Cleans trailing commas in objects and arrays to ensure valid JSON deserialization.
- **Secret Redaction**: Masks high-entropy authorization tokens, Bearer headers, and API keys (e.g. matching `sk-`, `ghp_`, `AKIA`, or JWT patterns) when exporting configurations or printing diagnostics.

### 9.3 Safe Fixer & Atomic Migration Engine (`fixer.py`)
- **Native Schema Preservation**: Edits client configurations while retaining target-specific key structures (e.g. Zed's nested `command` map vs. standard `command`/`args` lists).
- **Atomic Backup Creation**: Automatically generates timestamped backups (`<path>.bak.<timestamp>`) prior to modifying configuration files.
- **Transactional Writes**: Writes updates to a temporary sibling file (`.<filename>.tmp`) and executes an atomic POSIX filesystem rename (`os.replace`).
- **Write Failure Rollback**: Restores original state from backup if any I/O exception occurs during the update process.
- **Monotonic SemVer Enforcement**: Prevents downgrades during automated patching, ensuring recommended versions are strictly greater than installed versions.

---

## 10. Supply Chain Tampering & Dynamic Schema Drift Prober

To defend against supply chain hijacking and dynamic prompt injection attacks, `mcp-vulnerabilities` provides runtime inspection modules:

### 10.1 Supply Chain Tamper Detector (`mcp_vulnerabilities.audit.tamper`)
- **Runtime Signature Drift**: Compares tool signatures advertised at runtime against static baseline passports in `data/passports.json.gz`.
- **Shadow Tool Injection Detection**: Flags any unadvertised tool dynamically registered by an MCP server as a `CRITICAL` severity vulnerability.
- **Parameter & Docstring Hijacking**: Detects mutated descriptions, inserted hidden system prompt injections, or added parameters that deviate from upstream passports.
- **Severity Scoring**: Computes aggregate tamper severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) with detailed structural diffs.

### 10.2 Behavioral Topology Prober (`mcp_vulnerabilities.audit.prober`)
- **STDIO Noise Filtering**: Isolates JSON-RPC messages on standard I/O by parsing only newline-delimited JSON objects, ignoring unstructured pre-initialization stderr/stdout logs from runtimes (e.g. Python warnings, Node deprecations).
- **Socket Disconnect Resilience**: Detects abrupt transport closes or socket timeouts during capability handshake and reports clean diagnostic errors without crashing.
- **Child Process Lifecycle Protection**: Wraps launched subprocesses with strict timeout guards and signal escalation (`SIGTERM` followed by `SIGKILL` and process tree cleanup), preventing orphan zombie processes.

---

## 11. Interactive Terminal Security Hub (`mcp_vulnerabilities.audit.hub`)

The Terminal Security Hub provides an interactive terminal interface (`mcp-vuln hub`) for reviewing multi-client security posture:
- **Alternate Screen Buffer**: Uses ANSI alternate screen buffer mode to preserve shell history.
- **Graceful SIGINT Handling**: Catches terminal interrupts (`Ctrl+C`) and cleanly restores cursor visibility and terminal modes.
- **Unified Diff Preview**: Displays colorized unified diff previews before applying safe version patches to configuration files.
- **CWE-150 ANSI Sanitization**: Strips escape sequences from external advisory text and repository names to prevent terminal injection attacks.
- **Headless Fallback**: Automatically degrades to non-interactive batch reporting when standard input is not a TTY (e.g. in CI/CD pipelines).

---

## 12. Empirical Invariant Testing Framework & DAG Orchestration Engine

To ensure verified reliability across all core components, the codebase includes empirical invariant test suites and DAG workflow automation:

### 12.1 26 Empirical Invariant Test Matrix (`tests/audit/`)
The suite validates system behavior across 8 critical subsystems:
- `test_audit_task59.py`: OSV 1.6 range integrity, deduplicator range collapsing, and mid-batch recovery.
- `test_audit_task60.py`: Universal 9-client discovery, BOM stripping, URL-safe comment removal, trailing comma tolerance, secret masking.
- `test_audit_task61.py`: Runtime signature drift, shadow tool injection, docstring prompt injection, parameter schema tampering.
- `test_audit_task62.py`: STDIO noise filtering, socket disconnect resilience, child process zombie cleanup.
- `test_audit_task63.py`: Polyglot schema preservation, atomic backups, transactional rollback, monotonic SemVer resolution.
- `test_audit_task64.py`: Headless fallback, unified diff preview, SIGINT terminal restoration, CWE-150 ANSI sanitization.
- `test_audit_task65.py`: Bit-for-bit SHA-256 byte equality across worker counts (1, 2, 4, 8), non-fatal worker crash isolation, content-addressed caching.
- `test_audit_task66.py`: "Only Servers with Tools" filter parity, zero-tool badge rendering, DOM XSS immunity, shard network retry button.

### 12.2 DAG Workflow Orchestration (`docs/audit/audit_and_benchmark_dag.yml`)
- Encodes the 14-task audit and benchmarking pipeline as a Directed Acyclic Graph.
- Supports topological sorting, parallel wave execution, and conditional execution policies (`on_success`, `on_failure`, `always`).

---

## 13. Competitive Benchmarking & Cumulative Synthesis Pipeline

The system incorporates rigorous competitive benchmarking against 10 leading industry solutions across four functional categories:
1. **Runtime MCP Guardians**: Verity (MCP Database Guard/Oracle), Anthropic Inspector SDK, Cursor Sandbox.
2. **Registry & Ecosystem Telemetry**: Smithery.ai, Glama.ai.
3. **Vulnerability Scanners**: Snyk, Semgrep, Trivy, OSV.dev.
4. **Supply Chain Security**: Sigstore/Cosign, SLSA Level 3, CycloneDX v1.6.

### 13.1 Master Deliverables
- **`docs/audit/CUMULATIVE_TECHNICAL_AUDIT_REPORT.md`**: Synthesis of all 8 empirical audits, 26 invariant verifications, and catalog of resolved defects.
- **`docs/audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md`**: Grand Unified Feature Matrix across 10 products, strategic gap analysis, and architectural blueprints for v1.2–v2.0 (Inline Reverse Proxy, AST Call-Graph Reachability, Sigstore Keyless Attestation, Composite Trust Scoring).



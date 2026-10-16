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

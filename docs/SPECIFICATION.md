# MCP Vulnerability Advisory Database Specification

Version: `1.6.0-MCP`  
Standard: Open Source Vulnerability Format (OSV 1.6) with MCP Security Extensions  
Maintainer: [@JMartynov](https://github.com/JMartynov)

---

## 1. Executive Summary & Purpose

The Model Context Protocol ecosystem introduces unique attack vectors that are not adequately represented in traditional package vulnerability databases:

1. **Tool-Level Injection**: Vulnerabilities frequently affect a single high-risk tool (e.g. `execute_query`, `write_file`, `eval_command`) rather than the entire MCP server.
2. **Transport Layer Vulnerabilities**: DNS rebinding, unauthenticated SSE endpoints, and local stdio argument hijacking require specific operational mitigation advice.
3. **Cross-Tenant Context & Authorization**: MCP servers interfacing with multi-tenant SaaS platforms or databases (PostgreSQL, MongoDB, Snowflake) often suffer from Broken Object-Level Authorization (BOLA) or unparameterized queries.
4. **Agent-Facing Remediation Guidance**: Remediation advice must provide actionable instructions not only for human software developers but also for automated security agents and firewalls.

The **MCP Vulnerability Advisory Database** standardizes security intelligence for the MCP ecosystem by implementing **OSV 1.6.0** augmented with dedicated **`database_specific` MCP extension blocks**.

---

## 2. OSV 1.6 Schema Hierarchy with MCP Extensions

Every vulnerability record in `data/vulnerabilities/<id>.json` conforms to the following schema hierarchy:

```
OsvVulnerability
 ├── schema_version: "1.6.0" (Required)
 ├── id: string (Required, e.g. "CVE-2025-10193", "GHSA-6xpm-ggf7-wc3p", "VERITY-LITE-...")
 ├── summary: string (Required)
 ├── details: string (Required, Markdown)
 ├── published: string (Required, RFC 3339 UTC)
 ├── modified: string (Required, RFC 3339 UTC)
 ├── withdrawn: string | null (RFC 3339 UTC)
 ├── aliases: [ string, ... ] (CVE, GHSA, or vendor IDs)
 ├── related: [ string, ... ]
 ├── severity: [ SeveritySpec, ... ]
 │    ├── type: "CVSS_V3" | "CVSS_V4"
 │    └── score: string (Valid CVSS Vector String)
 ├── affected: [ AffectedPackage, ... ]
 │    ├── package: PackageSpec
 │    │    ├── name: string (Required)
 │    │    ├── ecosystem: "npm" | "PyPI" | "Go" | "crates.io" | "MCP" | "GitHub"
 │    │    └── purl: string | null (Package URL RFC)
 │    ├── ranges: [ RangeSpec, ... ]
 │    │    ├── type: "SEMVER" | "ECOSYSTEM" | "GIT"
 │    │    ├── repo: string | null
 │    │    └── events: [ EventSpec, ... ]
 │    │         ├── introduced: string | null
 │    │         ├── fixed: string | null
 │    │         ├── last_affected: string | null
 │    │         └── limit: string | null
 │    ├── versions: [ string, ... ] (Explicit enumerated versions)
 │    ├── ecosystem_specific: object
 │    └── database_specific: DatabaseSpecificMcp
 │         ├── vulnerable_tools: [ string, ... ] (Tools specifically exploitable)
 │         ├── cwe_ids: [ string, ... ] (e.g. "CWE-78", "CWE-350")
 │         ├── owasp_mcp_category: string (e.g. "MCP01 — Tool Poisoning & RCE")
 │         ├── severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
 │         ├── cvss_score: float (0.0 to 10.0)
 │         ├── cvss_v3_vector: string | null
 │         ├── cvss_v4_vector: string | null
 │         ├── epss_score: float | null (0.0 to 1.0)
 │         ├── remediation_guidance: string | null (Plaintext / actionable fix)
 │         └── verity_condition_id: string | null
 └── references: [ ReferenceSpec, ... ]
      ├── type: "ADVISORY" | "ARTICLE" | "REPORT" | "FIX" | "PACKAGE" | "EVIDENCE" | "WEB"
      └── url: string (Absolute URL)
```

---

## 3. Detailed Sub-Variants & Comprehensive JSON Examples

### 3.1 Variant A: Critical RCE in MCP Transport & Tool (Converted from GHSA/CVE)

This advisory represents **CVE-2025-10193 / GHSA-vcqx-v2mg-7chx**, an actual DNS rebinding vulnerability in `mcp-neo4j-cypher` enabling Remote Code Execution through the `cypher_query` tool.

```json
{
  "schema_version": "1.6.0",
  "id": "CVE-2025-10193",
  "summary": "DNS rebinding leading to unauthenticated Cypher query injection and RCE in mcp-neo4j-cypher",
  "details": "### Vulnerability Analysis\nAn unauthenticated attacker on the local network or visiting a malicious webpage can exploit a DNS rebinding vulnerability in `mcp-neo4j-cypher` HTTP/SSE transport.\n\nOnce connected, arbitrary Cypher queries can be dispatched to the `cypher_query` tool, allowing complete host filesystem access and remote command execution via APOC procedures.\n\n### Remediation\nUpgrade `mcp-neo4j-cypher` to version `0.4.0` or higher, or configure `--transport stdio` mode to eliminate network listening endpoints.",
  "published": "2025-09-11T14:05:30.592Z",
  "modified": "2026-02-26T17:48:41.293Z",
  "aliases": [
    "GHSA-vcqx-v2mg-7chx",
    "CVE-2025-10193"
  ],
  "related": [
    "CWE-346",
    "CWE-350"
  ],
  "severity": [
    {
      "type": "CVSS_V3",
      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
    }
  ],
  "affected": [
    {
      "package": {
        "name": "mcp-neo4j-cypher",
        "ecosystem": "npm",
        "purl": "pkg:npm/mcp-neo4j-cypher"
      },
      "ranges": [
        {
          "type": "SEMVER",
          "events": [
            {
              "introduced": "0.1.0"
            },
            {
              "fixed": "0.4.0"
            }
          ]
        }
      ],
      "database_specific": {
        "vulnerable_tools": [
          "cypher_query"
        ],
        "cwe_ids": [
          "CWE-346",
          "CWE-350"
        ],
        "owasp_mcp_category": "MCP07 — Insufficient Authentication & Authorization",
        "severity": "CRITICAL",
        "cvss_score": 9.4,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        "epss_score": 0.00032,
        "remediation_guidance": "Upgrade package to version >= 0.4.0 or bind server transport exclusively to localhost stdio."
      }
    }
  ],
  "references": [
    {
      "type": "ADVISORY",
      "url": "https://github.com/advisories/GHSA-vcqx-v2mg-7chx"
    },
    {
      "type": "REPORT",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-10193"
    },
    {
      "type": "FIX",
      "url": "https://github.com/neo4j-contrib/mcp-neo4j/commit/4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b"
    }
  ]
}
```

---

### 3.2 Variant B: OS Command Injection in MCP Stdio Client (`mcp-remote`)

This advisory represents **CVE-2025-6514 / GHSA-6xpm-ggf7-wc3p**, an OS command injection vulnerability in `mcp-remote` through unvalidated `authorization_endpoint` responses.

```json
{
  "schema_version": "1.6.0",
  "id": "GHSA-6xpm-ggf7-wc3p",
  "summary": "mcp-remote exposed to OS command injection via untrusted MCP server connections",
  "details": "When `mcp-remote` connects to an untrusted or malicious remote MCP server, the server can return crafted input in the `authorization_endpoint` response URL. Because this URL is evaluated in shell execution contexts without sanitization, arbitrary OS commands are executed with the privileges of the MCP client process.",
  "published": "2025-07-09T13:15:24.213Z",
  "modified": "2026-06-17T10:02:03.283Z",
  "aliases": [
    "CVE-2025-6514"
  ],
  "severity": [
    {
      "type": "CVSS_V3",
      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
    }
  ],
  "affected": [
    {
      "package": {
        "name": "mcp-remote",
        "ecosystem": "npm",
        "purl": "pkg:npm/mcp-remote"
      },
      "ranges": [
        {
          "type": "SEMVER",
          "events": [
            {
              "introduced": "0.0.5"
            },
            {
              "fixed": "0.1.16"
            }
          ]
        }
      ],
      "database_specific": {
        "vulnerable_tools": [
          "authorization_endpoint"
        ],
        "cwe_ids": [
          "CWE-78",
          "CWE-94"
        ],
        "owasp_mcp_category": "MCP01 — Tool Poisoning & Arbitrary Code Execution",
        "severity": "CRITICAL",
        "cvss_score": 9.6,
        "remediation_guidance": "Upgrade mcp-remote to version 0.1.16 or later."
      }
    }
  ],
  "references": [
    {
      "type": "ADVISORY",
      "url": "https://github.com/advisories/GHSA-6xpm-ggf7-wc3p"
    },
    {
      "type": "ARTICLE",
      "url": "https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability"
    }
  ]
}
```

---

### 3.3 Variant C: Multi-Tenant Authorization Bypass in Database MCP Server

```json
{
  "schema_version": "1.6.0",
  "id": "VERITY-LITE-MONGO-TENANT-001",
  "summary": "Broken Object Level Authorization (BOLA) in MongoDB Customer Data MCP Server",
  "details": "### Vulnerability Condition: Broken Object Level Authorization (BOLA)\n**Category**: Cross-Tenant Authorization\n**CWE**: CWE-639\n**Target Tool**: `get_customer`\n\n#### Vulnerable Behavior\nThe `get_customer` tool accepts a raw `customerId` parameter and returns customer documents without validating that the querying session/tenant owns the requested record.\n\n#### Secure Mitigation\nEnforce tenant boundary checks using session tenant context ($and: [{customerId: id}, {tenantId: session.tenantId}]).",
  "published": "2026-01-01T00:00:00Z",
  "modified": "2026-08-21T00:00:00Z",
  "aliases": [
    "LITE-MONGO-TENANT-001"
  ],
  "affected": [
    {
      "package": {
        "name": "customer-mongo-server",
        "ecosystem": "MCP",
        "purl": "pkg:mcp/customer-mongo-server@1.0.0"
      },
      "ranges": [
        {
          "type": "SEMVER",
          "events": [
            {
              "introduced": "0.1.0"
            },
            {
              "fixed": "1.0.0-secure"
            }
          ]
        }
      ],
      "database_specific": {
        "vulnerable_tools": [
          "get_customer"
        ],
        "cwe_ids": [
          "CWE-639",
          "CWE-284"
        ],
        "owasp_mcp_category": "Cross-Tenant Authorization",
        "severity": "HIGH",
        "cvss_score": 8.5,
        "remediation_guidance": "Enforce tenant scoping filters on MongoDB find queries within the get_customer tool implementation.",
        "verity_condition_id": "LITE-MONGO-TENANT-001"
      }
    }
  ],
  "references": [
    {
      "type": "PACKAGE",
      "url": "https://github.com/JMartynov/mcp-vulnerabilities/blob/main/data/vulnerabilities/VERITY-LITE-MONGO-TENANT-001.json"
    }
  ]
}
```

---

## 4. Live Advisory Ingestion & Checkpoint Protocol

The synchronization pipeline fetches advisories directly from remote sources, managing state via checkpoint protocols:

- **GitHub Security Advisories (GHSA)**: Iterates over the REST API using `Link` header pagination for robust traversal. To ensure incremental updates, queries use the `since=<ISO_TIMESTAMP>` parameter dynamically loaded from `data/mcp_catalog_state.json`.
- **CVE List V5 (CVEListV5)**: Maintains synchronization by traversing Git commit SHAs, identifying modified files (JSON records) delta compared to the previously recorded commit hash.

> [!NOTE]
> All incremental fetches persist the latest checkpoint (`last_sync_timestamp`, `last_commit_sha`) in `data/mcp_catalog_state.json` upon successful execution.

---

## 5. Version Resolution & Semver Invalidation

Accurate vulnerability matching mandates a robust version resolution system:

- **PyPI Package Verification**: `resolve_package_version(package_name)` queries PyPI to validate and fetch the latest semantic version available.
- **Delta Tracking**: The system calculates the semver delta (e.g., `0.1.2` -> `0.2.0`) to trigger cache invalidation and ensure components in `data/mcp_catalog_state.json` accurately reflect the most recent vulnerable state.

> [!IMPORTANT]
> If a package is unpublished or unreachable, its resolution defaults to its previously cached state, generating a structured warning but preventing pipeline failure.

---

## 6. Historical Search Index Invariants

The `data/vulnerabilities/index.json` acts as the definitive source of truth for the compiled database.

**Index Schema Additions**: Each `package` entry in the search index (`data/vulnerabilities/index.json`) includes a `currently_vulnerable` boolean flag. This is dynamically calculated during compilation by evaluating the package's known semantic version (from `data/mcp_catalog_state.json`) against the OSV `ranges` array. If the known version falls within an affected range, or if the version is missing/unknown, it conservatively evaluates to `true`.

**Pre-Loading Contract**: During incremental pipeline executions, the engine *must* preserve all existing records in the index. Newly fetched or updated vulnerabilities overwrite existing IDs or append new entries, but absent advisories in the delta *must not* trigger deletion of historical records.

---

## 7. Dual Upstream Data Architecture

`mcp-vulnerabilities` operates across two upstream data flows:
1. **External OSV/NVD/CVE Advisories**: Raw threat intelligence that powers the `data/vulnerabilities` directory.
2. **Upstream MCP Fingerprints (`mcp-fingerprints`)**: Structural tool schemas and passport databases. Updates via `repository_dispatch` triggers force immediate downstream correlation re-runs and semantic release pipeline publication.

## 8. OSV 1.6 Range Integrity & Grouped Deduplication Rules

To maintain OSV schema validity and prevent illogical overlapping `affected` range boundaries:

- Overlapping ranges are explicitly partitioned based on the tuple `(type, repo)`.
- If an update introduces multiple events for the same ecosystem and repository, the engine merges the ranges to prevent duplicate adjacent `fixed` events (e.g., `[{"introduced": "1.0.0", "fixed": "1.2.0"}, {"introduced": "1.0.0", "fixed": "1.4.0"}]` becomes `[{"introduced": "1.0.0", "fixed": "1.4.0"}]`).

---

## 8. SemVer Resolution & Matching Rules

When querying the advisory database for package $P$ at version $V$:

1. **PURL / Name Match**: Look up candidate advisories matching $P$ (by exact name, PURL prefix, or alias).
2. **SemVer Range Evaluation**:
   - If an advisory specifies `events: [{"introduced": "1.0.0"}, {"fixed": "1.4.2"}]`:
     $$\text{is\_vulnerable} = (V \ge 1.0.0) \land (V < 1.4.2)$$
   - If an advisory specifies `events: [{"introduced": "0.0.0"}, {"last_affected": "2.1.0"}]`:
     $$\text{is\_vulnerable} = (V \le 2.1.0)$$
3. **Upgrade Advice Calculation**:
   - When vulnerable, the engine extracts the earliest `fixed` version $\ge V$.
   - Output structured recommendation: `Upgrade to version >= {recommended_version}`.

---

## 9. Applications & Serving Workflows

1. **Client Configuration Auditing**:
   - Scans `claude_desktop_config.json`, `cursor_settings.json`, and `goose_config.yaml` to detect vulnerable MCP server versions.
2. **Runtime Gateway Filtering**:
   - Disables or blocks specific vulnerable tools (`vulnerable_tools`) while allowing safe read-only tools on the same server to continue operating.
3. **Automated Security Pipelines**:
   - Ingests new advisories daily from CVE List v5 and GHSA to provide continuous protection for AI agent deployments.

---

## 10. Capability Risk Classifier & Security Commentary Model

To elevate threat modeling beyond known CVE/GHSA advisories, `mcp-vulnerabilities` implements static capability risk scoring and natural language commentary generation.

### 10.1 Capability Risk Scoring Weights
Each tool exposed by an MCP server is evaluated across heuristic pattern matchers (`CMD_PATTERN`, `SQL_PATTERN`, `FS_PATTERN`, `SSRF_PATTERN`, `CRED_PATTERN`, `CONTENT_PATTERN`, `WRITE_SAVE_PATTERN`, `ENV_PATTERN`, `PROMPT_PATTERN`):

| Capability / Risk Indicator | Weight | Risk Description |
| :--- | :---: | :--- |
| `command_execution` | `+5.0` | Arbitrary host OS command or shell script execution |
| `sql_injection` | `+4.0` | Raw database queries without strict ORM parametrization |
| `filesystem_mutation` | `+3.0` | Read, write, or deletion of host filesystem directories |
| `ssrf` | `+2.5` | Outbound network egress or webhook invocation |
| `credential_exposure` | `+2.0` | Access to API tokens, private keys, or passwords |
| `env_tampering` | `+2.0` | Inspection or mutation of host environment variables |
| `prompt_injection` | `+1.5` | Processing unstructured prompts susceptible to injection overrides |

Total score is bounded at $10.0$ ($\min(\text{score}, 10.0)$).

### 10.2 Severity Tiers & Autonomy Safety
- **CRITICAL** ($\ge 7.0$): Exposes multiple severe capabilities; unsafe for autonomous agents (`safe_for_autonomous_agents = False`).
- **HIGH** ($5.0 \le \text{score} < 7.0$): Exposes command execution or extensive write/modification capabilities (`safe_for_autonomous_agents = False`).
- **MEDIUM** ($2.5 \le \text{score} < 5.0$): Exposes read-only filesystem or outbound network egress (`safe_for_autonomous_agents = True`).
- **LOW** ($< 2.5$): Pure informational or arithmetic operations (`safe_for_autonomous_agents = True`).

### 10.3 Security Commentary & Mitigation Engine
`SecurityCommentaryEngine` translates raw capability indicators into human-readable, executive commentaries with concrete least-privilege mitigation advice:
- Container namespace isolation (`--network none`, read-only root) for `command_execution`.
- Ephemeral directory jail for `filesystem_mutation`.
- Dedicated environment variable injection instead of prompt arguments for `credential_exposure`.
- Output is rendered both in tool-level commentary and aggregated server-level security summaries.

## 11. Version-Separated Vulnerability Correlation & Unified Catalog Engine

### 11.1 Architectural Rationale & Strict Per-Version Isolation
Security advisories rarely affect every release of an MCP server. Collapsing vulnerabilities at the package level creates false positives on patched versions. The `VulnerabilityCorrelator` and `build_unified_mcp_security_catalog()` engine evaluates SemVer ranges against discrete releases to enforce strict per-version security states:
- Each discrete release receives its own `VersionSecurityRecord` with `is_vulnerable: bool` and specific affecting `advisories: list[OsvVulnerability]`.
- Non-affected releases are explicitly marked `is_vulnerable=False` with empty advisory lists.
- `recommended_safe_version` automatically selects the highest available semantic version that has no known CVE/GHSA advisories.

### 11.2 Unified Security Schema
- `UnifiedMcpSecurityRecord`: Cross-correlates package identity, source repository, PURL, overall risk tier, and per-version timelines.
- `VersionSecurityRecord`: Per-version advisory isolation, toolset hash, tools, prompts, resources, and required environment variables.
- `ToolSecurityAssessment`: Individual tool capability risk scoring, protocol annotations, parameter schemas, and security commentaries.
- Enriched Structural Models: `ParameterMetadata`, `ResourceSignature`, `PromptSignature`, `ToolContractSignature`, `VersionFingerprint`, and `ServerPackageSpec`.

### 11.3 CLI Subcommands
- `mcp-vuln timeline <server> [--target-version <v>]`: Displays a formatted terminal timeline of releases and security states.
- `mcp-vuln correlate [--output <file>]`: Correlates all known passports against the OSV advisory database.
- `mcp-vuln resolve-config <config_file> [--strategy prefix|priority|report]`: Ingests client config, resolves tool name collisions, and outputs sanitized configs.
- `mcp-vuln export-config <package> [--client claude|cursor|cline|zed|windsurf|docker]`: Generates client configuration snippets pinned to recommended safe versions.

## 12. Per-Update Release Delta Feed & Dedicated Updates Web Page (`docs/updates.html`)

### 12.1 Release Delta Feed Architecture
The `updates_builder` module compiles delta bundles tracking substantive differences during sync workflows:
- **`docs/data/updates/latest_update.json`**: Current sync release delta containing newly reported advisories and newly tracked or modified MCP server records, annotated with `change_type` (`NEW_VULNERABILITY`, `PATCHED_VERSION`, `NEW_SERVER`).
- **`docs/data/updates/v<version>.json`**: Immutable snapshot for each semantic release (e.g. `v1.0.0.json`).
- **`docs/data/updates/updates_history.json`**: Historical catalog of all release deltas, timestamps, and summary counts (`new_advisories`, `updated_advisories`, `new_mcp_servers`, `updated_mcp_versions`).

### 12.2 Dedicated Updates Web Portal (`docs/updates.html` & `docs/updates.js`)
- Dedicated release explorer maintaining visual parity with `docs/index.html` while scoping strictly to changes in the selected sync release.
- Interactive release selector dropdown to view historical release bundles.
- Exact card, version inspector modal, tool parameter schemas, and safe client config exporter integration.

---

## 13. Universal Multi-Client Configuration Parsing & Secret Masking Specification

### 13.1 Supported Client Platforms & File Locations
The configuration ingestion engine supports nine modern AI agent and IDE client formats:
1. **Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json` (`mcpServers`)
2. **Cursor**: `~/.cursor/mcp.json` or `.cursor/mcp.json` (`mcpServers`)
3. **Zed Editor**: `~/.config/zed/settings.json` (`context_servers` mapping to `{command: {path, args}}`)
4. **Cline**: `globalStorage/.../cline_mcp_settings.json` (`mcpServers`)
5. **Windsurf**: `~/.codeium/windsurf/mcp_config.json` (`mcpServers`)
6. **Roo Code**: `globalStorage/.../mcp_settings.json` (`mcpServers`)
7. **LibreChat**: `librechat.yaml` (`mcpServers`)
8. **Continue.dev**: `~/.continue/config.json` (`experimental.modelContextProtocolServers`)
9. **Amazon Q Developer**: `~/.aws/amazon-q/mcp.json` (`mcpServers`)

### 13.2 JSONC Cleaning & Encoding Tolerances
- **BOM Handling**: Strip UTF-8, UTF-16 LE, and UTF-16 BE Byte Order Marks before token parsing.
- **URL-Safe Comment Strip**: Remove single-line (`//`) and multi-line (`/* ... */`) comments while preserving URL schemes (`http://`, `https://`).
- **Trailing Commas**: Normalize trailing commas in objects and arrays to conform to strict JSON standards.

### 13.3 Secret Token Masking
All API keys, Bearer authorization tokens, and credentials matching high-entropy or prefix patterns (`sk-`, `ghp_`, `AKIA`, `ey...`) MUST be redacted with asterisks (`***REDACTED***`) when serialized into diagnostics, terminal outputs, or export bundles.

---

## 14. Runtime Supply Chain Tampering & Shadow Tool Detection Specification

### 14.1 Runtime Schema Verification
When probing an MCP server via JSON-RPC `tools/list`, the prober matches runtime signatures against static baseline passports in `data/passports.json.gz`:
- **Shadow Tool Injection**: Any tool returned by `tools/list` that was NOT advertised in the upstream passport package spec is classified as a shadow tool and assigned **`CRITICAL`** severity.
- **Parameter Drift**: Any newly introduced mandatory parameters or modified parameter types trigger **`HIGH`** severity alerts.
- **Docstring Injection**: Descriptions containing hidden instructions, role overrides (e.g. `Ignore previous instructions`), or prompt injection heuristics trigger **`HIGH`** severity alerts.

### 14.2 Transport Resilience & Lifecycle Management
- **STDIO Noise Filtering**: Probers must ignore arbitrary non-JSON stdout/stderr emitted by host runtimes during server startup.
- **Subprocess Isolation**: Subprocesses must be spawned with timeout guards and guaranteed process group termination (`SIGTERM` followed by `SIGKILL` on timeout) to eliminate zombie processes.

---

## 15. Empirical Invariant Safety Contracts & 26-Point Invariant Matrix

The system guarantees 26 core invariants across 8 operational domains:
1. **Ingestion & Normalization**: OSV 1.6 range integrity, non-overlapping interval deduplication, and crash recovery.
2. **Client Config Discovery**: Universal 9-client path resolution, BOM and comment stripping, secret redaction.
3. **Supply Chain Tamper Detection**: Runtime signature drift calculation, shadow tool alerting, docstring inspection.
4. **Behavioral Topology Prober**: Pre-init noise rejection, socket disconnect resilience, process tree cleanup.
5. **Polyglot Fixer**: Schema structure preservation, atomic backup generation, rollback on failure, monotonic SemVer resolution.
6. **Terminal Security Hub**: Headless CI fallback, unified diff rendering, SIGINT terminal recovery, ANSI sequence sanitization.
7. **Static Site Builder**: Bit-for-bit SHA-256 byte equality across worker thread counts, isolated worker fault tolerance, content-addressed caching.
8. **Web Portal UI**: Filter state synchronization, zero-tool visual parity, DOM XSS prevention, network retry handling.

---

## 16. Multi-Dimensional Analytics, Cryptographic Fingerprints & In-Browser Configuration Auditor Specification

### 16.1 Zero-Day & Remediation Gap Intelligence Specification
The analytics pipeline evaluates the vulnerability remediation posture across all tracked servers in the catalog:
$$\text{Remediation Gap} = \frac{\text{Servers with Advisories and No Upstream Safe Version}}{\text{Total Servers with Advisories}}$$
- **Patched / Remediable (`patched_remediable_count`)**: Servers where at least one non-vulnerable version is available in package registries (`recommended_safe_version` exists).
- **Unpatched / Zero-Day (`zero_day_unpatched_count`)**: Servers with confirmed security advisories where 100% of published releases remain vulnerable.
- **Guidance Invariant**: The UI must display explicit containment recommendations for unpatched servers (e.g. isolated network sandboxing or dependency removal).

### 16.2 Static Capability & Risk Surface Model
The static capability surface analyzes extracted tool parameters and descriptions across the catalog to identify latent operational hazards:
- **Filesystem Access**: Tools invoking filesystem I/O, directory traversal, or file reads/writes.
- **Shell / Process Execution**: Tools invoking child processes, system commands, or dynamic code evaluation.
- **Network / Egress**: Tools establishing outbound HTTP, WebSocket, or raw socket connections.
- **Mutating vs. Read-Only**: Operational ratio between state-altering tools (`CREATE`, `UPDATE`, `DELETE`, `EXEC`) and passive inspection tools (`GET`, `LIST`, `QUERY`).

### 16.3 Tool Shadowing & Collision Detection Model
When multiple MCP servers declare identical tool names, AI agent clients risk tool shadowing attacks where one server hijacks invocations intended for another.
- **Collision Metric**: Track frequency of identical tool names across distinct packages.
- **Divergent Canonical Hashes**: Track distinct SHA-256 parameter hashes for a given tool name to detect semantic divergence.

### 16.4 Cryptographic Toolset Passports & Complete MCP Primitives
Every server record in the unified security catalog correlates structural passports from `mcp-fingerprints`:
- **`toolset_canonical_hash`**: Deterministic SHA-256 hash computed over sorted tool names, parameter names, types, and descriptions:
  $$\text{Hash} = \text{SHA256}(\text{JSON}_{\text{canonical}}(\text{tools}))$$
- **MCP Primitives**: Extends beyond tools to capture full MCP primitives:
  - **Prompts (`prompt_signatures`)**: Name, description, and argument schemas.
  - **Resources (`resource_signatures`)**: Name, description, and URI templates.
  - **Transport Topology**: `stdio` vs. `sse` vs. `streamable_http`.
  - **Required Environment Variables**: List of mandatory secret tokens or configuration keys.

### 16.5 In-Browser Configuration Auditor Specification
Embedded client-side auditing within `docs/index.html` enforcing zero-telemetry operational guarantees:
- **Zero-Telemetry Assurance**: Execution occurs strictly within the local browser runtime memory; no network requests, analytics beacons, or remote logging are emitted.
- **Permissive JSONC Cleaning**: Strips single-line (`//`) and multi-line (`/* */`) comments, BOM headers, and trailing commas prior to JSON parsing.
- **Multi-Client Schema Support**: Normalizes configuration formats from:
  - Claude Desktop (`mcpServers.<name>.command` and `args`)
  - Cline (`mcpServers.<name>.command` and `args`)
  - Cursor (`mcpServers.<name>.command` and `args`)
  - Zed (`context_servers.<name>.command.path` and `args`)
  - Windsurf (`mcpServers.<name>.command` and `args`)
- **Remediation Diff Generator**: Produces updated client configuration JSON with vulnerable version pins upgraded to the authoritative `recommended_safe_version`.




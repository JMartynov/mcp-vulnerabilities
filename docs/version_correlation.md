# Version-Separated Vulnerability Correlation Engine

This document details the architectural design, algorithms, and data structures of the version-separated vulnerability correlation engine in `mcp_vulnerabilities.fingerprints.correlator`.

---

## 1. Executive Overview

Traditional package vulnerability databases associate vulnerabilities broadly at the package level. In the MCP ecosystem, this approach causes severe false positive rates: an MCP server release may patch an exploitable tool or vulnerability in version `1.2.0`, while older versions (`<1.2.0`) remain vulnerable. Clients and security scanners checking only package names would flag `1.2.0` as unsafe.

The **Version-Separated Vulnerability Correlation Engine** solves this by:
1. Mapping every discrete release of an MCP server to an isolated `VersionSecurityRecord`.
2. Evaluating OSV 1.6 SemVer and Ecosystem ranges against each individual version.
3. Explicitly setting `is_vulnerable: false` and `advisories: []` on non-affected versions.
4. Calculating the `recommended_safe_version` identifying the highest stable release with zero known CVEs.
5. Evaluating tool capability risks and security commentary per tool contract.

---

## 2. Core Components & Data Flow

```
┌──────────────────────────────────────┐       ┌──────────────────────────────────────┐
│ Upstream Passports                   │       │ OSV Vulnerability Database           │
│ (data/passports.json.gz)             │       │ (data/vulnerabilities/*.json)        │
└──────────────────┬───────────────────┘       └──────────────────┬───────────────────┘
                   │                                              │
                   └──────────────────────┬───────────────────────┘
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │ VulnerabilityCorrelator               │
                      │ - Ecosystem / package name matching   │
                      │ - SemVer range evaluator              │
                      │ - VersionVulnerabilityState mapper    │
                      └──────────────────┬────────────────────┘
                                         │
                                         ▼
                      ┌───────────────────────────────────────┐
                      │ build_unified_mcp_security_catalog    │
                      │ - UnifiedMcpSecurityRecord            │
                      │ - VersionSecurityRecord (per version) │
                      │ - ToolSecurityAssessment (per tool)   │
                      │ - recommended_safe_version calculator │
                      └──────────────────┬────────────────────┘
                                         │
                                         ▼
                      ┌───────────────────────────────────────┐
                      │ Downstream Consumers:                 │
                      │ - CLI (mcp-vuln timeline / correlate) │
                      │ - Static Site Builder & 32 shards     │
                      │ - Multi-Client Config Exporter & Hub  │
                      └───────────────────────────────────────┘
```

---

## 3. Data Models (`mcp_vulnerabilities.catalog.models`)

### 3.1 `UnifiedMcpSecurityRecord`
The top-level model representing a single MCP server package across all its releases:
- `package_name`: Canonical package identifier (e.g. `@modelcontextprotocol/server-postgres`).
- `ecosystem`: Target ecosystem (`npm`, `pypi`, `golang`, `generic`).
- `repository_url`: Upstream source repository.
- `purl`: Canonical Package URL (RFC).
- `overall_risk_tier`: Composite static capability risk tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- `total_vulnerabilities`: Aggregate count of unique CVEs/GHSAs across all versions.
- `recommended_safe_version`: Highest non-vulnerable release string (or `null` if none available).
- `versions`: List of `VersionSecurityRecord` entries, one per tracked release.

### 3.2 `VersionSecurityRecord`
Represents the security state of a specific release version:
- `version`: SemVer string (e.g. `0.2.1`).
- `is_vulnerable`: Boolean flag. Strictly `false` if no active advisory affects this version.
- `advisories`: List of `OsvVulnerability` records specifically affecting this release.
- `toolset_hash`: SHA-256 fingerprint of the exposed tool signatures.
- `tools`: List of `ToolSecurityAssessment` objects evaluating tool risks and commentary.
- `prompts`: List of prompt signatures.
- `resources`: List of resource template signatures.
- `required_env`: Environment variables declared by this version.

### 3.3 `ToolSecurityAssessment`
Detailed capability analysis for an individual tool:
- `name`: Tool identifier (e.g. `read_query`, `write_file`).
- `description`: Tool description from server capabilities.
- `capability_risk_tier`: Risk score tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- `capability_score`: Numeric capability risk score ($0.0$ to $10.0$).
- `safe_for_autonomous_agents`: Boolean flag indicating whether the tool is safe to execute without human confirmation.
- `parameters`: List of `ParameterMetadata` describing input schemas and types.
- `security_commentary`: Plaintext least-privilege operational advice.

---

## 4. Range Matching & Version Resolution Algorithms

### 4.1 SemVer Range Matching
The correlation engine evaluates whether version $v$ is affected by checking range events:
- `introduced`: Version at which the vulnerability began affecting the package (inclusive).
- `fixed`: Version that remediates the vulnerability (exclusive; version $\ge$ `fixed` is safe).
- `last_affected`: Final version affected (inclusive; version $>$ `last_affected` is safe).
- `limit`: Upper boundary for ecosystem evaluation.

### 4.2 Safe Version Recommendation
To compute `recommended_safe_version`:
1. Collect all published versions for the server package.
2. Filter for versions where `is_vulnerable == False`.
3. Sort candidate versions in descending order according to semantic versioning precedence (`packaging.version.Version`).
4. Select the highest non-prerelease version (falling back to highest prerelease if all versions are prereleases).
5. If all versions are vulnerable, set `recommended_safe_version = None` and flag `no_fix_available = True`.

---

## 5. CLI Usage & Commands

### Timeline Inspection
Inspect the full version security timeline for any MCP server in the terminal:
```bash
uv run mcp-vuln timeline @modelcontextprotocol/server-postgres
uv run mcp-vuln timeline mcp-server-git --target-version 0.1.2
```

### Full Catalog Correlation
Export the complete correlated catalog of all passports against the OSV advisory database:
```bash
uv run mcp-vuln correlate --output data/correlated_catalog.json
```

### Safe Client Configuration Export
Generate a configuration snippet pinned to the recommended safe version:
```bash
uv run mcp-vuln export-config @modelcontextprotocol/server-filesystem --client claude
uv run mcp-vuln export-config @modelcontextprotocol/server-postgres --client cursor
uv run mcp-vuln export-config mcp-server-git --client zed
```

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

## 4. SemVer Resolution & Matching Rules

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

## 5. Applications & Serving Workflows

1. **Client Configuration Auditing**:
   - Scans `claude_desktop_config.json`, `cursor_settings.json`, and `goose_config.yaml` to detect vulnerable MCP server versions.
2. **Runtime Gateway Filtering**:
   - Disables or blocks specific vulnerable tools (`vulnerable_tools`) while allowing safe read-only tools on the same server to continue operating.
3. **Automated Security Pipelines**:
   - Ingests new advisories daily from CVE List v5 and GHSA to provide continuous protection for AI agent deployments.

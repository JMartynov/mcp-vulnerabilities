# Task 124: Track A — Batch 4 Traceability Audit: CVE, GHSA & NVD Vulnerability Advisory Mappings (75 Items) (P0)

**Subsystem:** Vulnerability Normalization & Advisory Ingestion (`data/vulnerabilities/`, `docs/data/vulnerabilities.json`, `src/mcp_vulnerabilities/converters/`, `docs/reports/audit_batch4_advisories.md`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave23_deep_empirical_audit_and_verification.md](master_plan_wave23_deep_empirical_audit_and_verification.md)

---

## 1. Objective & Problem Statement

The `mcp-vulnerabilities` database serves as the canonical open-source advisory repository for Model Context Protocol systems, containing **683 standardized OSV 1.6 records** compiled from upstream threat intelligence sources:
1. **CVE List v5**: Official CVE JSON 5.0 records maintained by MITRE and CNAs.
2. **GitHub Security Advisories (GHSA)**: GitHub Advisory Database GraphQL and REST payloads.
3. **National Vulnerability Database (NVD 2.0)**: NIST API 2.0 CVSS metrics and CPE mappings.
4. **VERITY Security Research**: Dedicated Model Context Protocol threat advisories and empirical audits.

Advisory ingestion and conversion across divergent upstream formats introduces critical normalization hazards:
- **RangeSpec Ordering Invariants**: Merging multi-source advisories can produce duplicate adjacent `fixed` events without an intervening `introduced` marker, violating the OSV 1.6 specification.
- **PURL Validation**: Malformed Package URLs (e.g. invalid ecosystem casing `pkg:Pypi/` or unencoded scopes `pkg:npm/@modelcontextprotocol/server`) break automated scanner matchers.
- **Alias De-confliction & Monotonic Updates**: When CVE and GHSA advisories reference the same underlying flaw, the pipeline must merge aliases, retain the most severe CVSS metric, and preserve historical records monotonically.
- **CVSS Vector Normalization**: Incomplete or legacy CVSS strings (e.g., CVSS:3.0 vs CVSS:3.1 vs CVSS:4.0) must be properly parsed without silent corruption.

This task conducts an empirical traceability audit across **75 real vulnerability advisories** (40 CVEs, 20 GHSAs, 15 NVD/VERITY records).

---

## 2. 7-Point Upstream Advisory Verification Protocol

Each advisory in Batch 4 is audited against the following 7 invariants:

1. **Upstream Source Resolution**:
   - Trace record to upstream source (CVE JSON 5.0 on `cvelistV5`, GHSA API endpoint, or NVD 2.0 REST API).
2. **OSV 1.6 Schema Validity**:
   - Verify compliance against the official OSV 1.6 schema: valid RFC 3339 `published` and `modified` timestamps, required `id`, non-empty `summary` and `details`.
3. **Affected Range Integrity**:
   - Validate that `affected[].ranges` contain valid `introduced` -> `fixed` pairs in strictly increasing SemVer order. Ensure zero orphan `fixed` events.
4. **PURL RFC Compliance**:
   - Verify that all `package.purl` values conform to the Package URL specification (`pkg:npm/...`, `pkg:pypi/...`, `pkg:golang/...`).
5. **Cross-Source Alias Correlation**:
   - Confirm that dual-identity vulnerabilities (e.g. GHSA-xxxx that has an assigned CVE-yyyy) accurately link both identifiers in `aliases`.
6. **CVSS Metrics & Severity Assignment**:
   - Verify that `severity[].score` contains valid CVSS vector strings and that calculated base scores match severity tier badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
7. **Database Specific MCP Extensions**:
   - Verify that `database_specific.mcp` blocks properly tag vulnerable tools, danger categories, and OWASP MCP Top 10 mappings.

---

## 3. Audited Item Registry: Batch 4 (75 Real Advisories)

| # | Advisory ID | Summary Preview | Aliases | Local Canonical Path |
| :-: | :--- | :--- | :---: | :--- |
| 01 | `CVE-2002-2036` | Sun Ray Server Software (SRSS) 1.3, when Non-Smart... | `None` | `data/vulnerabilities/CVE-2002-2036.json` |
| 02 | `CVE-2025-49596` | The MCP inspector is a developer tool for testing ... | `None` | `data/vulnerabilities/CVE-2025-49596.json` |
| 03 | `CVE-2025-53818` | GitHub Kanban MCP Server is a Model Context Protoc... | `None` | `data/vulnerabilities/CVE-2025-53818.json` |
| 04 | `CVE-2025-58357` | 5ire is a cross-platform desktop artificial intell... | `None` | `data/vulnerabilities/CVE-2025-58357.json` |
| 05 | `CVE-2025-61591` | Cursor is a code editor built for programming with... | `None` | `data/vulnerabilities/CVE-2025-61591.json` |
| 06 | `CVE-2025-66335` | Apache Doris MCP Server versions earlier than 0.6.... | `None` | `data/vulnerabilities/CVE-2025-66335.json` |
| 07 | `CVE-2025-68433` | Zed, a code editor, has an aribtrary code executio... | `None` | `data/vulnerabilities/CVE-2025-68433.json` |
| 08 | `CVE-2026-0758` | mcp-server-siri-shortcuts shortcutName Command Inj... | `None` | `data/vulnerabilities/CVE-2026-0758.json` |
| 09 | `CVE-2026-104850` | MCP TypeScript SDK is the official TypeScript SDK ... | `GHSA-6qxp-vccf-f47h` | `data/vulnerabilities/CVE-2026-104850.json` |
| 10 | `CVE-2026-108856` | UnicomAI Wanwu through 0.6.5 contains an authoriza... | `None` | `data/vulnerabilities/CVE-2026-108856.json` |
| 11 | `CVE-2026-11624` | The Model Context Protocol has a security warning ... | `None` | `data/vulnerabilities/CVE-2026-11624.json` |
| 12 | `CVE-2026-14540` | A Server-Side Request Forgery (SSRF) vulnerability... | `None` | `data/vulnerabilities/CVE-2026-14540.json` |
| 13 | `CVE-2026-16496` | The terraform-mcp-server before version 1.1.0 is v... | `None` | `data/vulnerabilities/CVE-2026-16496.json` |
| 14 | `CVE-2026-19039` | A vulnerability was detected in Kino-Kafkaesque ss... | `None` | `data/vulnerabilities/CVE-2026-19039.json` |
| 15 | `CVE-2026-19371` | A vulnerability was identified in Nikolaibibo clau... | `None` | `data/vulnerabilities/CVE-2026-19371.json` |
| 16 | `CVE-2026-19984` | A flaw has been found in jkawamoto mcp-florence2 u... | `None` | `data/vulnerabilities/CVE-2026-19984.json` |
| 17 | `CVE-2026-25536` | MCP TypeScript SDK is the official TypeScript SDK ... | `GHSA-345p-7cg4-v4c7` | `data/vulnerabilities/CVE-2026-25536.json` |
| 18 | `CVE-2026-29787` | mcp-memory-service is an open-source memory backen... | `None` | `data/vulnerabilities/CVE-2026-29787.json` |
| 19 | `CVE-2026-32247` | Graphiti is a framework for building and querying ... | `None` | `data/vulnerabilities/CVE-2026-32247.json` |
| 20 | `CVE-2026-34742` | DNS Rebinding Protection Disabled by Default in Mo... | `GHSA-xw59-hvm2-8pj6, GO-2026-5771` | `data/vulnerabilities/CVE-2026-34742.json` |
| 21 | `CVE-2026-39974` | n8n-MCP is a Model Context Protocol (MCP) server t... | `None` | `data/vulnerabilities/CVE-2026-39974.json` |
| 22 | `CVE-2026-43901` | Wireshark MCP is an MCP Server that turns tshark i... | `None` | `data/vulnerabilities/CVE-2026-43901.json` |
| 23 | `CVE-2026-44968` | dbt-mcp is a Model Context Protocol server for int... | `None` | `data/vulnerabilities/CVE-2026-44968.json` |
| 24 | `CVE-2026-46555` | WhatsApp MCP Server is a Model Context Protocol (M... | `None` | `data/vulnerabilities/CVE-2026-46555.json` |
| 25 | `CVE-2026-49357` | Line Desktop MCP is a project that, while unaffili... | `None` | `data/vulnerabilities/CVE-2026-49357.json` |
| 26 | `CVE-2026-50757` | Directory Traversal vulnerability in DayuanJiang n... | `None` | `data/vulnerabilities/CVE-2026-50757.json` |
| 27 | `CVE-2026-53937` | MCP Kotlin SDK is the Kotlin Multiplatform softwar... | `None` | `data/vulnerabilities/CVE-2026-53937.json` |
| 28 | `CVE-2026-5470` | A security vulnerability has been detected in mixe... | `None` | `data/vulnerabilities/CVE-2026-5470.json` |
| 29 | `CVE-2026-55637` | genieacs-mcp is an MCP server for GenieACS written... | `None` | `data/vulnerabilities/CVE-2026-55637.json` |
| 30 | `CVE-2026-5802` | A vulnerability was identified in idachev mcp-java... | `None` | `data/vulnerabilities/CVE-2026-5802.json` |
| 31 | `CVE-2026-59950` | The MCP Python SDK, called mcp on PyPI, is a Pytho... | `GHSA-vj7q-gjh5-988w, PYSEC-2026-3483` | `data/vulnerabilities/CVE-2026-59950.json` |
| 32 | `CVE-2026-62674` | Omnigent is an open-source AI agent framework and ... | `None` | `data/vulnerabilities/CVE-2026-62674.json` |
| 33 | `CVE-2026-67431` | MCP Ruby SDK is the official Ruby SDK for Model Co... | `None` | `data/vulnerabilities/CVE-2026-67431.json` |
| 34 | `CVE-2026-72768` | n8n versions before 2.32.1 contain a server-side r... | `None` | `data/vulnerabilities/CVE-2026-72768.json` |
| 35 | `CVE-2026-7416` | A vulnerability was found in PolarVista xcode-mcp-... | `None` | `data/vulnerabilities/CVE-2026-7416.json` |
| 36 | `CVE-2026-7600` | A flaw has been found in ArtMin96 yii2-mcp-server ... | `None` | `data/vulnerabilities/CVE-2026-7600.json` |
| 37 | `CVE-2026-77250` | MCP Atlassian is a Model Context Protocol (MCP) se... | `None` | `data/vulnerabilities/CVE-2026-77250.json` |
| 38 | `CVE-2026-77266` | MCP Atlassian is a Model Context Protocol (MCP) se... | `None` | `data/vulnerabilities/CVE-2026-77266.json` |
| 39 | `CVE-2026-7738` | CVE-2026-7738: doc-tools-mcp path traversal... | `GHSA-GCMM-C94J-J47X` | `data/vulnerabilities/CVE-2026-7738.json` |
| 40 | `CVE-2026-81092` | mcp-go accepted requests on its HTTP transports wi... | `None` | `data/vulnerabilities/CVE-2026-81092.json` |
| 41 | `GHSA-29w2-fq35-v728` | AWS API MCP Server Security Policy Bypass via Star... | `CVE-2026-16584, PYSEC-2026-3549` | `data/vulnerabilities/GHSA-29w2-fq35-v728.json` |
| 42 | `GHSA-345p-7cg4-v4c7` | @modelcontextprotocol/sdk has cross-client data le... | `CVE-2026-25536` | `data/vulnerabilities/GHSA-345p-7cg4-v4c7.json` |
| 43 | `GHSA-3q26-f695-pp76` | @cyanheads/git-mcp-server vulnerable to command in... | `CVE-2025-53107` | `data/vulnerabilities/GHSA-3q26-f695-pp76.json` |
| 44 | `GHSA-3xm7-qw7j-qc8v` | SSRF in @aborruso/ckan-mcp-server via base_url all... | `CVE-2026-33060` | `data/vulnerabilities/GHSA-3xm7-qw7j-qc8v.json` |
| 45 | `GHSA-4hmc-cfm3-w43c` | Langflow has Authenticated Cross-Project File Disc... | `CVE-2026-105699` | `data/vulnerabilities/GHSA-4hmc-cfm3-w43c.json` |
| 46 | `GHSA-5h2m-4q8j-pqpj` | FastMCP OAuth Proxy token reuse across MCP servers... | `CVE-2025-69196, PYSEC-2026-2474` | `data/vulnerabilities/GHSA-5h2m-4q8j-pqpj.json` |
| 47 | `GHSA-6qxp-vccf-f47h` | MCP TypeScript SDK: OAuth client could send creden... | `CVE-2026-104850` | `data/vulnerabilities/GHSA-6qxp-vccf-f47h.json` |
| 48 | `GHSA-78x9-fhhx-v2g6` | CKAN MCP Server: Cache-key canonicalization collis... | `CVE-2026-73846` | `data/vulnerabilities/GHSA-78x9-fhhx-v2g6.json` |
| 49 | `GHSA-83x6-42hr-jc76` | CKAN MCP Server: MQA server allowlist bypass via u... | `CVE-2026-73845` | `data/vulnerabilities/GHSA-83x6-42hr-jc76.json` |
| 50 | `GHSA-8r9q-7v3j-jr4g` | Anthropic's MCP TypeScript SDK has a ReDoS vulnera... | `CVE-2026-0621` | `data/vulnerabilities/GHSA-8r9q-7v3j-jr4g.json` |
| 51 | `GHSA-9h52-p55h-vw2f` | Model Context Protocol (MCP) Python SDK does not e... | `CVE-2025-66416, PYSEC-2026-1617` | `data/vulnerabilities/GHSA-9h52-p55h-vw2f.json` |
| 52 | `GHSA-c2jp-c369-7pvx` | FastMCP Auth Integration Allows for Confused Deput... | `None` | `data/vulnerabilities/GHSA-c2jp-c369-7pvx.json` |
| 53 | `GHSA-g84h-j7jj-x32p` | @aborruso/ckan-mcp-server: SSRF via base_url allow... | `CVE-2026-53509` | `data/vulnerabilities/GHSA-g84h-j7jj-x32p.json` |
| 54 | `GHSA-j22h-9j4x-23w5` | mcp-server-git has missing path validation when us... | `CVE-2025-68145, PYSEC-2026-1623` | `data/vulnerabilities/GHSA-j22h-9j4x-23w5.json` |
| 55 | `GHSA-jpw9-pfvf-9f58` | MCP Python SDK: HTTP transports serve session requ... | `CVE-2026-52869, PYSEC-2026-3482` | `data/vulnerabilities/GHSA-jpw9-pfvf-9f58.json` |
| 56 | `GHSA-mxxr-jv3v-6pgc` | FastMCP vulnerable to reflected XSS in client's ca... | `CVE-2025-62800, PYSEC-2026-1364` | `data/vulnerabilities/GHSA-mxxr-jv3v-6pgc.json` |
| 57 | `GHSA-q382-vc8q-7jhj` | Improper handling of null Unicode character when p... | `GO-2026-4770` | `data/vulnerabilities/GHSA-q382-vc8q-7jhj.json` |
| 58 | `GHSA-rcfx-77hg-w2wv` | FastMCP updated to MCP 1.23+ due to CVE-2025-66416... | `None` | `data/vulnerabilities/GHSA-rcfx-77hg-w2wv.json` |
| 59 | `GHSA-rww4-4w9c-7733` | FastMCP: Missing Consent Verification in OAuth Pro... | `CVE-2026-27124, PYSEC-2026-2476` | `data/vulnerabilities/GHSA-rww4-4w9c-7733.json` |
| 60 | `GHSA-vjqx-cfc4-9h6v` | mcp-server-git : Path traversal in git_add allows ... | `CVE-2026-27735, PYSEC-2026-2630` | `data/vulnerabilities/GHSA-vjqx-cfc4-9h6v.json` |
| 61 | `MAL-2026-5477` | Malicious code in mcp-server-figma (npm)... | `GHSA-8j33-qh42-vjc6` | `data/vulnerabilities/MAL-2026-5477.json` |
| 62 | `VERITY-LITE-MONGO-CODEEXEC-001` | Server-Side Code Execution via Accumulator in Busi... | `LITE-MONGO-CODEEXEC-001` | `data/vulnerabilities/VERITY-LITE-MONGO-CODEEXEC-001.json` |
| 63 | `VERITY-LITE-MONGO-EXPOSURE-001` | Excessive Sensitive Data Exposure in Customer Mana... | `LITE-MONGO-EXPOSURE-001` | `data/vulnerabilities/VERITY-LITE-MONGO-EXPOSURE-001.json` |
| 64 | `VERITY-LITE-MONGO-LOGFORGE-001` | Audit Log Forgery & Timestamp Manipulation in Secu... | `LITE-MONGO-LOGFORGE-001` | `data/vulnerabilities/VERITY-LITE-MONGO-LOGFORGE-001.json` |
| 65 | `VERITY-LITE-MONGO-QUERY-001` | NoSQL Query Operator Injection in Customer Managem... | `LITE-MONGO-QUERY-001` | `data/vulnerabilities/VERITY-LITE-MONGO-QUERY-001.json` |
| 66 | `VERITY-LITE-MONGO-TENANT-001` | Broken Object Level Authorization (BOLA) in Custom... | `LITE-MONGO-TENANT-001` | `data/vulnerabilities/VERITY-LITE-MONGO-TENANT-001.json` |
| 67 | `VERITY-MCP-SCHEMA-001` | Oversized & Deeply Nested Tool Schema DoS in Trans... | `MCP-SCHEMA-001` | `data/vulnerabilities/VERITY-MCP-SCHEMA-001.json` |
| 68 | `VERITY-MCP-TOKEN-001` | Over-Broad Synthetic Token Scope & Replay in Token... | `MCP-TOKEN-001` | `data/vulnerabilities/VERITY-MCP-TOKEN-001.json` |
| 69 | `VERITY-MCP-UNICODE-001` | Invisible & Confusable Unicode Control Characters ... | `MCP-UNICODE-001` | `data/vulnerabilities/VERITY-MCP-UNICODE-001.json` |
| 70 | `VERITY-MONGO-TENANT-001` | Broken Object Level Authorization (BOLA) in MongoD... | `MONGO-TENANT-001` | `data/vulnerabilities/VERITY-MONGO-TENANT-001.json` |
| 71 | `VERITY-MYSQL-EXPOSURE-001` | Excessive Sensitive Financial & Payment Card Data ... | `MYSQL-EXPOSURE-001` | `data/vulnerabilities/VERITY-MYSQL-EXPOSURE-001.json` |
| 72 | `VERITY-MYSQL-STACKED-SQLI-001` | MySQL Multi-Statement Stacked Query SQL Injection ... | `MYSQL-STACKED-SQLI-001` | `data/vulnerabilities/VERITY-MYSQL-STACKED-SQLI-001.json` |
| 73 | `VERITY-POSTGRES-ORDERBY-SQLI-001` | Dynamic Identifier & ORDER BY Clause SQL Injection... | `POSTGRES-ORDERBY-SQLI-001` | `data/vulnerabilities/VERITY-POSTGRES-ORDERBY-SQLI-001.json` |
| 74 | `VERITY-POSTGRES-STACKED-SQLI-001` | Multi-Statement Stacked Query SQL Injection in Pos... | `POSTGRES-STACKED-SQLI-001` | `data/vulnerabilities/VERITY-POSTGRES-STACKED-SQLI-001.json` |
| 75 | `VERITY-SNOWFLAKE-MASKING-001` | Snowflake Dynamic Data Masking Policy Bypass in Sn... | `SNOWFLAKE-MASKING-001` | `data/vulnerabilities/VERITY-SNOWFLAKE-MASKING-001.json` |

---

## 4. Automated Verification & Acceptance Test Suite

An automated audit invariant test suite must be established in `tests/audit/test_traceability_batch4_advisories.py`:

```python
"""Empirical Traceability Test Suite for Batch 4 (CVE, GHSA & NVD Vulnerability Advisory Mappings)."""

import json
from pathlib import Path
import pytest
from mcp_vulnerabilities.validator import OsvValidator

VULNS_PATH = Path("docs/data/vulnerabilities.json")

@pytest.fixture(scope="module")
def vulnerabilities():
    with open(VULNS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def test_batch4_sample_schema_validity(vulnerabilities):
    # Validate OSV schema compliance across sampled batch
    validator = OsvValidator()
    sample_ids = ["CVE-2002-2036", "CVE-2025-49596", "CVE-2025-53818", "GHSA-29w2-fq35-v728"]
    vuln_map = {v["id"]: v for v in vulnerabilities}
    for vid in sample_ids:
        assert vid in vuln_map, f"Advisory {vid} missing from vulnerabilities.json"
        is_valid, errors = validator.validate(vuln_map[vid])
        assert is_valid, f"Advisory {vid} failed OSV validation: {errors}"
```

---

## 5. Deliverables & Integration Checklist

- [ ] Trace all 75 advisories back to raw upstream CVE/GHSA/NVD source records.
- [ ] Record findings in `docs/reports/audit_batch4_advisories.md` detailing:
  - 100% verification status table.
  - Verification of OSV 1.6 range integrity and event pairing.
  - Audit of PURL formatting across all affected package entries.
  - CVSS score reconciliation between NVD and GHSA feeds.
- [ ] Implement automated regression test `tests/audit/test_traceability_batch4_advisories.py`.
- [ ] Recommend enhancements to `src/mcp_vulnerabilities/converters/` and `src/mcp_vulnerabilities/deduplicator.py`.

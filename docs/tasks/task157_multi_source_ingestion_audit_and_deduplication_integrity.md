# Task 157: Deep Audit, Ingestion Robustness, and Deduplication Integrity across All Vulnerability Sources

## Status: IN PROGRESS
**Priority:** High  
**Components:** Ingestion Pipelines, Deduplication Engine, OSV Schema Validation, Synchronization Cursors  
**Scope:** 9 Upstream Vulnerability & Threat Intelligence Sources, 817 Advisory Records, Disjoint-Set Union (DSU) Fusion Engine  

---

## 1. Executive Summary & Objective

The `mcp-vulnerabilities` platform aggregates, normalizes, and correlates security advisories and supply chain intelligence across heterogeneous ecosystem feeds. To guarantee **100% data reliability**, zero dropped records, accurate delta synchronization, and deterministic cross-source deduplication, this task establishes a deep technical audit of each source's ingestion pipeline, synchronization markers, and fusion algorithms.

---

## 2. In-Depth Research: 9 Upstream Sources

### 2.1 GitHub Security Advisories (GHSA)
* **Ingestion Path:** [`src/mcp_vulnerabilities/converters/ghsa.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/converters/ghsa.py) & [`pipeline.py: _sync_ghsa_api`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/pipeline.py)
* **API Mechanism:** GraphQL `securityAdvisories` API and REST `/advisories` with cursor pagination (`after: cursor`, page size 100).
* **Miss Prevention:**
  - Queries across all relevant ecosystems: `NPM`, `PIP`, `GO`, `RUST`.
  - Scans for MCP-related package names and keywords (`modelcontextprotocol`, `mcp-server`, `mcp`).
  - Handles secondary rate limits with exponential backoff (`tenacity` retry policy).
* **Update / Change Tracking:**
  - Caches `last_updated_at` in `data/vulnerabilities/sync_state.json`.
  - Subsequent syncs pass `updatedSince: <last_updated_at>`, guaranteeing ingestion of reclassified, amended, or withdrawn advisories.
* **Deduplication Strategy:**
  - GHSAs reference CVE IDs in `advisory.identifiers` or `aliases`.
  - Merged via `AdvisoryFusionEngine` where CVE ID takes precedence for the canonical identifier while GHSA formatted Markdown is preserved for `details`.

---

### 2.2 National Vulnerability Database (NVD)
* **Ingestion Path:** [`src/mcp_vulnerabilities/converters/nvd.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/converters/nvd.py) & [`pipeline.py: _sync_nvd_api`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/pipeline.py)
* **API Mechanism:** NVD 2.0 REST API (`https://services.nvd.nist.gov/rest/json/cves/2.0`).
* **Miss Prevention:**
  - Cursor pagination with `startIndex` and `resultsPerPage=2000`.
  - Evaluates MCP keyword patterns (`modelcontextprotocol`, `FastMCP`, `mcp-server`) and CPE vendor configurations.
  - Strict compliance with NVD rate limits (sleep intervals between requests).
* **Update / Change Tracking:**
  - Incremental queries leverage `lastModStartDate` and `lastModEndDate` bounded by `last_scan_utc`.
* **Deduplication Strategy:**
  - Authoritative source for CVSS v3.1/v4.0 vectors and metrics.
  - Scores override vendor estimates during fusion.

---

### 2.3 CVE Project (CVEListV5)
* **Ingestion Path:** [`src/mcp_vulnerabilities/converters/cve_json5.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/converters/cve_json5.py) & [`pipeline.py: _sync_cvelist_delta`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/pipeline.py)
* **API Mechanism:** Direct Git tree analysis of the official `CVEProject/cvelistV5` repository.
* **Miss Prevention:**
  - Comprehensive full scans index `cves/YYYY/` trees.
  - Checks affected package arrays and problem types.
* **Update / Change Tracking:**
  - High-performance Git delta tracking using `last_marker` (Git commit SHA).
  - Sync inspects `git diff --name-only <last_marker> HEAD` to parse only changed or newly assigned CVE records within seconds.
* **Deduplication Strategy:**
  - Serves as the primary root of canonical naming for all `CVE-YYYY-NNNNN` identifiers.

---

### 2.4 OSV.dev (Open Source Vulnerabilities)
* **Ingestion Path:** [`src/mcp_vulnerabilities/converters/osv_dev.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/converters/osv_dev.py)
* **API Mechanism:** OSV Batch Query API (`/v1/querybatch`) and consolidated ecosystem exports (`all.zip`).
* **Miss Prevention:**
  - Exact package name matching across the entire MCP server catalog (6,258 discovered packages).
* **Update / Change Tracking:**
  - OSV records maintain RFC 3339 `modified` timestamps.
  - Ingestion updates local records whenever `remote.modified > local.modified`.
* **Deduplication Strategy:**
  - Native OSV schema maps directly to `OsvVulnerability`. Cross-references in `aliases` link directly into the canonical alias graph.

---

### 2.5 PyPA Advisory Database
* **Ingestion Path:** [`src/mcp_vulnerabilities/converters/pypa.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/converters/pypa.py)
* **API Mechanism:** Direct ingestion from `pypa/advisory-database` repository.
* **Miss Prevention:**
  - Scans all YAML/OSV files under `vulns/` for Python MCP packages.
* **Update / Change Tracking:**
  - Tracked via Git commit sha markers.
* **Deduplication Strategy:**
  - PyPA `PYPA-` IDs cluster with CVE and GHSA aliases; version constraints use PyPI normalized semver.

---

### 2.6 GitLab Advisory Database
* **Ingestion Path:** [`src/mcp_vulnerabilities/converters/gitlab.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/converters/gitlab.py)
* **API Mechanism:** Ingestion from `gitlab-org/advisories-community` repository.
* **Miss Prevention:**
  - Iterates package subdirectories across `npm` and `pypi`.
* **Update / Change Tracking:**
  - Git commit delta synchronization via `last_marker`.
* **Deduplication Strategy:**
  - `GLAD-` identifiers are clustered as aliases under the canonical CVE or GHSA ID.

---

### 2.7 OpenSSF Malicious Packages
* **Ingestion Path:** [`src/mcp_vulnerabilities/threat_intel/openssf_malicious.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/threat_intel/openssf_malicious.py) & [`converters/openssf_malware.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/converters/openssf_malware.py)
* **Mechanism:** OpenSSF malware feeds and OSV `MAL-` feed.
* **Miss Prevention:**
  - Memory-indexed cache over the full 6,258 discovered package names with instant `O(1)` hash lookup.
* **Update / Change Tracking:**
  - Ingested on hourly cron schedules via `OpenSsfMaliciousSync().sync_upstream()`.
* **Deduplication Strategy:**
  - Packages flagged as deliberate malware are categorized under `composite_risk_tier: MALICIOUS` with full provenance links.

---

### 2.8 Exploitation & Threat Intelligence (CISA KEV & EPSS)
* **Ingestion Path:** [`src/mcp_vulnerabilities/threat_intel/cisa_kev.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/threat_intel/cisa_kev.py) & [`epss.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/threat_intel/epss.py)
* **Mechanism:**
  - CISA KEV JSON catalog (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`).
  - FIRST.org EPSS API (`https://api.first.org/data/v1/epss`).
* **Miss Prevention:**
  - Batched queries for every CVE present across all 817 records.
* **Update / Change Tracking:**
  - 24-hour cache TTL; daily automated refreshes.
* **Deduplication Strategy:**
  - Enrichment fields (`is_cisa_kev`, `epss_score`, `epss_percentile`) attach non-destructively to existing records.

---

### 2.9 Verity MCP Auditor & Community Disclosures
* **Ingestion Path:** [`src/mcp_vulnerabilities/converters/verity.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/converters/verity.py) & [`markdown_cve.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/converters/markdown_cve.py)
* **Mechanism:** Hand-curated MCP vulnerability writeups and research disclosures.
* **Miss Prevention:**
  - Automated recursive scanning of all markdown and json files in `data/sources/`.
* **Update / Change Tracking:**
  - File modification times and sha256 checksum tracking.
* **Deduplication Strategy:**
  - PURL and package name canonicalization.

---

## 3. Cross-Source Deduplication & Fusion Architecture

All records pass through the **Disjoint-Set Union (DSU) Fusion Engine** ([`src/mcp_vulnerabilities/dedup/fusion.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/dedup/fusion.py)):

```
[GHSA Feed] ──┐
[NVD Feed]  ──┼──> [Canonical Alias Graph] ──> [DSU Cluster Grouping] ──> [Field Fusion] ──> [Canonical OSV Record]
[CVE v5]    ──┤
[GitLab]    ──┘
```

1. **Identifier Resolution:**
   - Precedence: `CVE-YYYY-NNNNN` > `GHSA-xxxx-xxxx-xxxx` > `GLAD-xxxx` > `PYPA-xxxx`.
   - All other encountered IDs are sorted deterministically into `aliases`.
2. **Field-Level Fusion Rules:**
   - **Summary:** Prioritizes concise NVD/CVE or GitLab summary (`len > 0`).
   - **Details:** Prioritizes detailed Markdown writeup from GHSA.
   - **Severity & CVSS:** NVD base scores take precedence over secondary calculations.
   - **Version Ranges:** Bounded intervals (`introduced`, `fixed`) are merged across feeds using strict semver comparisons.
   - **References:** Deduplicated and normalized using [`dedup/url_normalizer.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/dedup/url_normalizer.py) (tracking parameters stripped, git prefixes cleaned).

---

## 4. Current Database Integrity Audit (Baseline)

* **Total Advisory Records:** 817
* **Validation Outcome:** **100% Valid** (0 invalid advisories, 0 schema violations via `OsvValidator`).
* **Unique Canonical IDs:** 817 unique IDs (0 duplicates).
* **Covered Ecosystems:** `['Go', 'MCP', 'PyPI', 'go', 'npm', 'rust']`.
* **Timestamp Consistency:** 100% of records satisfy `published <= modified` and RFC 3339 constraints.
* **Reference URL Sanitization:** 100% of references use valid protocols (`https://`, `http://`, `git://`).

---

## 5. Identified Hardening Tasks & Action Items

1. **CVSS Vector to Float Extraction in Matcher:**
   - Enhance `_extract_severity_info` in [`matcher.py`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/audit/matcher.py) to parse CVSS v3.1 vector strings into severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) when numeric scores are absent.
2. **Sync State Cursor Resiliency:**
   - Add automated schema migration and fallback for `data/vulnerabilities/sync_state.json` if corrupted or interrupted during network drops.
3. **Automated Cross-Source Regression Synthesis:**
   - Author a test suite verifying that ingesting an advisory from 3 sources simultaneously produces an identical deterministic fused record.

---

## 6. Acceptance Criteria

- [x] Comprehensive architectural research documented for all 9 upstream sources.
- [x] Full validation sweep completed across all 817 records in `data/vulnerabilities/` (100% valid, 0 schema errors, 0 duplicate IDs).
- [ ] Unit tests verifying CVSS vector string severity extraction in `VulnerabilityMatcher`.
- [ ] Deterministic multi-source fusion verified with fuzzing/mock fixtures.
- [ ] Task registered in repository project task tracking with full documentation parity.

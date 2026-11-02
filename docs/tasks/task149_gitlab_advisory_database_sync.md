# Task 149: GitLab Advisory Database Synchronization & Multi-Ecosystem Ingestion (P1)

**Subsystem:** Multi-Ecosystem Advisory Ingestion (`src/mcp_vulnerabilities/discovery/gitlab.py`, `src/mcp_vulnerabilities/converters/gitlab.py`, `src/mcp_vulnerabilities/pipeline.py`)  
**Priority:** `P1`  
**Target Wave:** Wave 27 (Threat Intelligence, Exploit Prediction & Multi-Source Deduplication)  
**Parent Plan:** [master_plan_wave27_threat_intel_exploit_prediction_and_deduplication.md](master_plan_wave27_threat_intel_exploit_prediction_and_deduplication.md)

---

## 1. Objective & Problem Statement

The Model Context Protocol ecosystem is intrinsically polyglot: while Python and TypeScript/npm dominate standard server implementations, production environments increasingly incorporate MCP servers written in Go (e.g. Docker and Kubernetes bridge servers), Rust, and JVM-based enterprise tools.

The **GitLab Advisory Database** (`gitlab.com/gitlab-org/advisories-community`) is one of the industry's most thorough and actively maintained open vulnerability feeds. Curated by GitLab's dedicated Vulnerability Research Team, it tracks thousands of security advisories across multiple ecosystems (npm, PyPI, Go, Maven, Gem) with high-fidelity CVSS v3.1 vectors, explicit version range boundaries, and remediation notes.

Currently, `mcp-vulnerabilities`:
1. Relies solely on OSV/GHSA for polyglot ecosystems (such as Go and multi-language MCP proxies).
2. Misses GitLab-curated CVE analyses that often publish earlier than or with richer CVSS scoring than standard NVD disclosures.
3. Lacks a parser capable of translating GitLab's custom YAML format and range notation into canonical OSV 1.6 structures.

Task 149 implements a dedicated **GitLab Advisory Database Ingestion, Range Normalization, and Multi-Ecosystem Converter Subsystem**.

---

## 2. Detailed Technical Requirements

### 2.1 GitLab Advisory Database Ingestion (`src/mcp_vulnerabilities/discovery/gitlab.py`)

Implement `GitLabAdvisorySync`:

1. **Repository Synchronization**:
   - Upstream Repo: `https://gitlab.com/gitlab-org/advisories-community`
   - Target Ecosystems for MCP: `npm/`, `pypi/`, `go/`
   - Ingestion Strategy:
     - Local mirror at `data/sources/gitlab/`.
     - Daily synchronization via Git sparse checkout or release archive:
       `https://gitlab.com/gitlab-org/advisories-community/-/archive/main/advisories-community-main.tar.gz`.
     - Record commit SHA in `data/sources/gitlab/.sync_marker` for incremental sync.
2. **GitLab Advisory YAML Schema**:
   Parse incoming YAML documents:
   ```yaml
   identifier: "CVE-2024-54133"
   identifiers:
     - "CVE-2024-54133"
     - "GHSA-w48q-v783-6mg3"
   package_slug: "npm/@modelcontextprotocol/server-postgres"
   title: "Improper Input Validation in MCP Postgres Server"
   description: "Model Context Protocol PostgreSQL server allows SQL injection..."
   date: "2026-02-14"
   pubdate: "2026-02-14"
   affected_range: ">=0.1.0 <0.3.2"
   fixed_versions:
     - "0.3.2"
   affected_versions: "All versions starting from 0.1.0 before 0.3.2"
   not_impacted: "All versions starting from 0.3.2"
   solution: "Upgrade to version 0.3.2 or above."
   urls:
     - "https://nvd.nist.gov/vuln/detail/CVE-2024-54133"
     - "https://github.com/modelcontextprotocol/servers/pull/123"
   cvss_v3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
   uuid: "3f82a170-8b4b-4a5c-9d6e-123456789abc"
   ```

---

### 2.2 GitLab Normalizer & OSV Converter (`src/mcp_vulnerabilities/converters/gitlab.py`)

Implement `GitLabConverter`:

1. **Ecosystem & Package Slug Mapping**:
   - `package_slug` format: `<ecosystem>/<package_name>`.
   - Examples:
     - `npm/@modelcontextprotocol/sdk` $\to$ ecosystem: `npm`, package: `@modelcontextprotocol/sdk`
     - `pypi/mcp` $\to$ ecosystem: `PyPI`, package: `mcp`
     - `go/github.com/mark3labs/mcp-go` $\to$ ecosystem: `Go`, package: `github.com/mark3labs/mcp-go`
2. **Range Syntax Normalization**:
   - GitLab `affected_range` expressions include:
     - `"<1.2.0"` $\to$ `introduced: "0"`, `fixed: "1.2.0"`
     - `">=1.0.0 <1.5.0"` $\to$ `introduced: "1.0.0"`, `fixed: "1.5.0"`
     - `">=1.0.0 <=1.4.2"` $\to$ `introduced: "1.0.0"`, `last_affected: "1.4.2"`
     - Disjoint ranges: `">=1.0.0 <1.2.0 || >=2.0.0 <2.1.0"` $\to$ two distinct OSV range objects.
3. **CVSS & Metadata Extraction**:
   - Convert `cvss_v3` vector string into OSV `severity`:
     ```json
     "severity": [
       {
         "type": "CVSS_V3",
         "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
       }
     ]
     ```
   - Retain `solution` as a top-level remediation instruction in `database_specific.remediation`.

---

### 2.3 Pipeline Integration & Alias Resolution (`src/mcp_vulnerabilities/pipeline.py`)

1. **Catalog Matching**:
   - Match parsed packages against active MCP catalog index.
2. **Alias Graph Feeding**:
   - Extract all entries in `identifiers` and pass them to the Canonical Alias Graph (Task 150) to fuse with matching CVE, GHSA, and OSV records.

---

## 3. Invariant Requirements & Verification Plan

### 3.1 Verification Invariants

- [ ] **INVARIANT_149_1 (Ecosystem Namespace Isolation)**: `package_slug` must be partitioned cleanly into valid OSV ecosystem identifiers (`npm`, `PyPI`, `Go`).
- [ ] **INVARIANT_149_2 (Range Disjunction Integrity)**: Compound disjunctive ranges (`||`) in GitLab advisories must be converted into multiple discrete OSV range objects without dropping version boundaries.
- [ ] **INVARIANT_149_3 (CVSS Vector Validity)**: When `cvss_v3` is present, it must conform to the standard FIRST CVSS v3.1 vector specification.
- [ ] **INVARIANT_149_4 (Alias Equivalence Preservation)**: All entries in `identifiers` must be cross-registered into the alias graph.

### 3.2 Automated Test Suite (`tests/test_gitlab_sync.py`)

Author a dedicated test suite with the following tests:
1. `test_gitlab_yaml_parsing`: Parses GitLab YAML records across npm, PyPI, and Go ecosystems.
2. `test_gitlab_range_syntax_conversion`: Tests single ranges (`<1.2.0`), inclusive upper bounds (`<=1.4.2`), and disjunctions (`||`).
3. `test_gitlab_cvss_vector_extraction`: Asserts CVSS 3.1 vector string is correctly stored in OSV severity array.
4. `test_gitlab_remediation_solution_preservation`: Validates that `solution` field is preserved in advisory details.
5. `test_gitlab_pipeline_dedup_integration`: Verifies a GitLab advisory with a CVE ID is linked to the canonical CVE record.

---

## 4. Deliverables & Integration Checklist

- [ ] Implement `src/mcp_vulnerabilities/discovery/gitlab.py` (`GitLabAdvisorySync`).
- [ ] Implement `src/mcp_vulnerabilities/converters/gitlab.py` (`GitLabConverter`).
- [ ] Integrate GitLab ingestion into `VulnerabilityPipeline.sync_all()`.
- [ ] Wire GitLab sync into `.github/workflows/daily_sync.yml`.
- [ ] Author test suite `tests/test_gitlab_sync.py` and verify all tests pass.
- [ ] Update `docs/SPECIFICATION.md` and `README.md` reflecting GitLab advisory database integration.

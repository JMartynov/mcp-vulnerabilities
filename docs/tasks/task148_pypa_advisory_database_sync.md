# Task 148: PyPA Advisory Database Synchronization & PEP 440 Normalization (P1)

**Subsystem:** Python Ecosystem Security & Ingestion (`src/mcp_vulnerabilities/discovery/pypa.py`, `src/mcp_vulnerabilities/converters/pypa.py`, `src/mcp_vulnerabilities/pipeline.py`)  
**Priority:** `P1`  
**Target Wave:** Wave 27 (Threat Intelligence, Exploit Prediction & Multi-Source Deduplication)  
**Parent Plan:** [master_plan_wave27_threat_intel_exploit_prediction_and_deduplication.md](master_plan_wave27_threat_intel_exploit_prediction_and_deduplication.md)

---

## 1. Objective & Problem Statement

Python represents the cornerstone language and runtime of the Model Context Protocol ecosystem, powering official SDKs (`mcp`), popular server frameworks (`FastMCP`), LLM orchestration libraries (`LangChain`, `LlamaIndex`), and data science tooling. 

The **Python Packaging Authority (PyPA)** maintains the authoritative **PyPA Advisory Database** (`github.com/pypa/advisory-database`), assigning canonical `PYSEC-*` identifiers and providing hand-curated security advisories for packages published on the Python Package Index (PyPI).

Currently, `mcp-vulnerabilities`:
1. Relies primarily on generic OSV aggregator dumps, which frequently lag PyPA-curated releases or miss Python-specific disclosures.
2. Experiences parsing inconsistencies when evaluating complex Python version constraints: PyPA advisories use **PEP 440** version specifications (e.g. `~=1.4.0`, `>=1.0.0,!=1.2.3,<2.0.0`, post-releases like `1.2.0.post1`, and dev-releases `1.0.0.dev4`), which fail or produce false positives under naive SemVer parsers.
3. Lacks a direct ingestion and converter pipeline for PyPA YAML advisories.

Task 148 implements a dedicated **PyPA Advisory Database Ingestion, PEP 440 Normalization, and OSV Conversion Engine**.

---

## 2. Detailed Technical Requirements

### 2.1 PyPA Advisory Ingestion (`src/mcp_vulnerabilities/discovery/pypa.py`)

Implement `PyPaAdvisorySync`:

1. **Upstream Source Synchronization**:
   - Upstream Repo: `https://github.com/pypa/advisory-database`
   - Path Structure: `vulns/<package_name>/PYSEC-<year>-<num>.yaml`
   - Ingestion Strategy:
     - Local mirror at `data/sources/pypa/`.
     - Git shallow sync (`--depth 1`) or release tarball download (`https://github.com/pypa/advisory-database/archive/refs/heads/main.tar.gz`) during daily sync.
     - Track commit HEAD SHA in `data/sources/pypa/.sync_marker` for incremental sync.
2. **PyPA YAML Parsing**:
   - PyPA advisories are formatted in YAML:
     ```yaml
     id: PYSEC-2025-42
     package:
       name: fastmcp
       ecosystem: PyPI
       purl: pkg:pypi/fastmcp
     summary: FastMCP Arbitrary File Read via Path Traversal in File Tool
     details: |
       FastMCP prior to version 0.4.1 does not sanitize tool arguments...
     aliases:
       - CVE-2025-10293
       - GHSA-q49j-9r9x-m94h
     modified: "2026-02-10T12:00:00Z"
     published: "2026-02-09T08:00:00Z"
     references:
       - type: FIX
         url: https://github.com/jlowin/fastmcp/commit/abcdef123456
       - type: ADVISORY
         url: https://nvd.nist.gov/vuln/detail/CVE-2025-10293
     affected:
       - package:
           name: fastmcp
           ecosystem: PyPI
         ranges:
           - type: ECOSYSTEM
             events:
               - introduced: "0"
               - fixed: "0.4.1"
         versions:
           - "0.1.0"
           - "0.2.0"
           - "0.4.0"
     ```

---

### 2.2 PEP 440 Normalization & OSV Conversion (`src/mcp_vulnerabilities/converters/pypa.py`)

Implement `PyPaConverter`:

1. **PEP 440 Version Clause Normalization**:
   - Utilize `packaging.version.Version` and `packaging.specifiers.SpecifierSet` to parse complex PEP 440 constraints.
   - **Range Decomposition**:
     - Handle compound exclusions (`>=1.0.0,!=1.2.0,<2.0.0`):
       - Split into contiguous OSV range events:
         - Segment 1: `introduced: "1.0.0"`, `fixed: "1.2.0"`
         - Segment 2: `introduced: "1.2.1"` (or next valid patch), `fixed: "2.0.0"`
     - Handle compatible releases (`~=1.4.2`):
       - Convert to `>= 1.4.2, == 1.4.*` $\to$ `introduced: "1.4.2"`, `fixed: "1.5.0"`.
     - Handle epoch versions (`1!2.0.0`) and post-releases (`1.0.0.post1`).
2. **OSV 1.6 Output Schema**:
   - Emit valid OSV JSON:
     - Retain `id: PYSEC-...`
     - Retain all `aliases` (`CVE-*`, `GHSA-*`)
     - Preserve full `references` array with classified types (`FIX`, `ADVISORY`, `WEB`, `REPORT`)
     - Ensure `affected[0].ranges` contains valid `introduced` / `fixed` or `introduced` / `last_affected` pairs.

---

### 2.3 Pipeline Integration & Alias Linking (`src/mcp_vulnerabilities/pipeline.py`)

1. **Catalog Matching**:
   - Filter PyPA advisories where `package.name` matches any PyPI package in the MCP catalog (e.g. `fastmcp`, `mcp`, `langchain-core`, `langchain-community`, `llama-index-core`, `uvicorn`).
2. **Canonical Graph Registration**:
   - Emit normalized records to the Canonical Alias Graph (Task 150), linking `PYSEC-*` records to corresponding `CVE-*` and `GHSA-*` clusters.

---

## 3. Invariant Requirements & Verification Plan

### 3.1 Verification Invariants

- [ ] **INVARIANT_148_1 (PEP 440 Clause Robustness)**: Every PyPA advisory must be parsed using `packaging.specifiers` without raising unhandled exceptions on complex clauses (`~=`, `!=`, `.post`, `.dev`).
- [ ] **INVARIANT_148_2 (OSV 1.6 Event Integrity)**: Every converted advisory must possess valid, alternating `introduced` and `fixed` (or `last_affected`) event pairs conforming to OSV schema v1.6.0.
- [ ] **INVARIANT_148_3 (Monotonic Alias Retention)**: All `CVE-*` and `GHSA-*` identifiers listed in PyPA `aliases` must be retained without loss during conversion.
- [ ] **INVARIANT_148_4 (Incremental Sync Idempotency)**: Syncing against the PyPA repository twice consecutively must produce zero redundant writes or duplicate entries.

### 3.2 Automated Test Suite (`tests/test_pypa_sync.py`)

Author a dedicated test suite with the following tests:
1. `test_pypa_yaml_parsing`: Parses sample PyPA YAML files and asserts complete data extraction.
2. `test_pep440_compound_range_decomposition`: Validates conversion of `>=1.0.0,!=1.2.0,<2.0.0` into disjoint OSV events.
3. `test_pep440_compatible_release_conversion`: Validates `~=2.3.0` correctly sets `fixed: "2.4.0"`.
4. `test_pep440_post_and_dev_release_handling`: Asserts versions with `.post1` and `.dev2` are correctly ordered.
5. `test_pypa_osv_conversion_schema_validity`: Validates converted records against the official OSV v1.6.0 JSON schema.
6. `test_pypa_pipeline_integration`: Ingests a mock PyPA advisory for `fastmcp` and verifies catalog linkage.

---

## 4. Deliverables & Integration Checklist

- [ ] Implement `src/mcp_vulnerabilities/discovery/pypa.py` (`PyPaAdvisorySync`).
- [ ] Implement `src/mcp_vulnerabilities/converters/pypa.py` (`PyPaConverter` with PEP 440 logic).
- [ ] Integrate PyPA ingestion into `VulnerabilityPipeline.sync_all()`.
- [ ] Wire PyPA sync into `.github/workflows/daily_sync.yml`.
- [ ] Author test suite `tests/test_pypa_sync.py` and verify all tests pass.
- [ ] Update `docs/SPECIFICATION.md` and `README.md` reflecting PyPA advisory coverage.

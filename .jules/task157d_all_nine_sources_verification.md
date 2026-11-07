# Task 157D: Unified 9-Source Ingestion and Provenance Verification Suite

## Objective
Author a comprehensive integration test suite `tests/test_all_nine_sources_ingestion.py` that verifies all 9 upstream vulnerability and threat intelligence sources produce schema-valid `OsvVulnerability` records passing `OsvValidator`, preserve provenance attribution, and handle delta updates properly.

## Requirements
1. In `tests/test_all_nine_sources_ingestion.py`:
   - Test each of the 9 sources with realistic mock input payloads:
     1. `ghsa.py` (GitHub Security Advisory GraphQL/REST)
     2. `nvd.py` (NVD 2.0 API CVE JSON)
     3. `cve_json5.py` (CVE Project CVEListV5 JSON format)
     4. `osv_dev.py` (OSV.dev JSON format)
     5. `pypa.py` (PyPA YAML advisory format)
     6. `gitlab.py` (GitLab Community advisory YAML/JSON)
     7. `openssf_malicious.py` / `openssf_malware.py` (OpenSSF Malware feed)
     8. `cisa_kev.py` & `epss.py` (CISA KEV enrichment & EPSS score mapping)
     9. `verity.py` & `markdown_cve.py` (Curated MCP community Markdown & JSON)
   - For every converter output, assert:
     - `OsvValidator.validate(record)` returns an empty list (0 validation errors).
     - ID matches expected format (`CVE-`, `GHSA-`, `PYPA-`, `GLAD-`, or `MAL-`).
     - Required fields (`id`, `summary`, `details`, `schema_version`, `affected`) are present and non-empty.
     - Affected packages have valid ecosystem strings (`npm`, `PyPI`, `Go`, `crates.io`, `MCP`) and valid PURLs.
     - Provenance URLs are correctly constructed by `resolve_provenance_urls()`.
2. Run `pytest tests/test_all_nine_sources_ingestion.py` and verify all tests pass.

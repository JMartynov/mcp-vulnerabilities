# Task: Wave 23 Track A — 300-Item Traceability & Extraction Audit (Tasks 121, 122, 123, 124)

## Overview & Mandate
You are assigned **Wave 23 Track A: 300-Item Source Traceability & Extraction Audit** for `mcp-vulnerabilities`.
Your task is to execute the empirical traceability audit specified across:
- `docs/tasks/task121_traceability_audit_batch1_npm_javascript.md` (Batch 1: 75 npm & JS servers)
- `docs/tasks/task122_traceability_audit_batch2_pypi_fastmcp.md` (Batch 2: 75 Python & PyPI FastMCP servers)
- `docs/tasks/task123_traceability_audit_batch3_go_rust_docker_github.md` (Batch 3: 75 Polyglot Go, Rust, Docker & GitHub Raw servers)
- `docs/tasks/task124_traceability_audit_batch4_cve_ghsa_nvd.md` (Batch 4: 75 CVE, GHSA & NVD advisory records)

## Instructions & Deliverables
1. **Audit Reports**:
   Generate detailed empirical audit reports under `docs/reports/wave23_audits/`:
   - `docs/reports/wave23_audits/audit_batch1_npm.md`
   - `docs/reports/wave23_audits/audit_batch2_pypi.md`
   - `docs/reports/wave23_audits/audit_batch3_polyglot.md`
   - `docs/reports/wave23_audits/audit_batch4_advisories.md`
   Each report must detail:
   - Audit methodology and the 7-Point verification protocol results.
   - Status table of audited items, upstream mapping, version fidelity, repository URL normalization, and discrepancy notes.
   - Root cause analysis of discovered edge cases (yanked versions, deprecations, invalid repository URLs, OSV range duplicate fixed events).
   - Concrete recommendations for the discovery and normalization engines.

2. **Automated Invariant Test Suites**:
   Author and verify comprehensive test suites under `tests/audit/`:
   - `tests/audit/test_traceability_batch1_npm.py`
   - `tests/audit/test_traceability_batch2_pypi.py`
   - `tests/audit/test_traceability_batch3_polyglot.py`
   - `tests/audit/test_traceability_batch4_advisories.py`
   Requirements:
   - Verify sample items exist in `docs/data/mcp_catalog_index.json` or `docs/data/vulnerabilities.json`.
   - Assert ecosystem tagging, version string validity, repository URL schema sanitization, and OSV range invariants.
   - MOCK all external HTTP/network calls using fixtures or local sample responses so the tests run 100% offline and deterministically in CI.

3. **Discovery & Pipeline Polish**:
   - Apply any necessary clean, non-breaking helper improvements or edge-case handling to `src/mcp_vulnerabilities/discovery/` or converters as identified in the task cards.

4. **Local Verification**:
   - Run `python3 -m pytest tests/audit/test_traceability_*.py -q` and ensure all tests pass.

## Non-Interactive Completion Directive
Execute all audit steps, write the 4 markdown reports under `docs/reports/wave23_audits/`, write and verify all 4 test suites under `tests/audit/`, verify that `pytest` passes, and commit directly without asking open-ended questions so this session cleanly transitions to `Completed`.

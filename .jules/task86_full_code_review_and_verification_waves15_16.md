# Task 86: Full Code Review & Empirical Verification Audit of Tasks 78–85 (P0)

**Target Wave:** Wave 17A (Quality Verification & Scorecard Audit)  
**Priority:** `P0` (Mandatory Pre-Release Quality Gate)  
**Master Plan:** [`docs/tasks/IMPLEMENTATION_PLAN_WAVE17_CODE_REVIEW_DOCS_AND_RELEASE_V120.md`](IMPLEMENTATION_PLAN_WAVE17_CODE_REVIEW_DOCS_AND_RELEASE_V120.md)

---

## 1. Architectural Context & Technical Objective

Waves 15 and 16 delivered 8 major engineering tasks:
- **Wave 15 (Tasks 78–83)**: Remediated all 10 defects (`DEFECT-W14-01` through `DEFECT-W14-10`) identified in [`docs/reports/code_review_wave14_portal_and_analytics.md`](../reports/code_review_wave14_portal_and_analytics.md) across `docs/app.js`, `docs/updates.js`, `docs/updates.html`, `docs/style.css`, `src/mcp_vulnerabilities/site_builder.py`, `tests/test_analytics.py`, `tests/test_wave14_portal.py`, and `tests/audit/test_audit_task80.py`.
- **Wave 16 (Tasks 84–85)**: Implemented the v1.2 strategic blueprints:
  - **Task 84**: Inline MCP Reverse Proxy Interceptor (`mcp-vuln proxy`) in `src/mcp_vulnerabilities/proxy/policy.py`, `src/mcp_vulnerabilities/proxy/interceptor.py`, `src/mcp_vulnerabilities/cli.py`, and `tests/test_mcp_proxy.py`.
  - **Task 85**: AST Interprocedural Call-Graph Reachability Engine in `src/mcp_vulnerabilities/analyzers/reachability/call_graph.py`, `src/mcp_vulnerabilities/transitive.py`, `src/mcp_vulnerabilities/cli.py`, and `tests/test_ast_reachability.py`.

This task performs a rigorous, line-by-line code review and empirical verification of all 8 tasks (Tasks 78–85), verifies that every invariant in their task contracts is satisfied, fixes any subtle edge cases if found, and publishes the comprehensive verification report.

---

## 2. Target Files & Isolation Boundaries

- **Primary Deliverables:**
  - `docs/reports/code_review_wave15_16_remediation_and_v12.md` (New comprehensive audit report)
  - `docs/reports/code_review_wave14_portal_and_analytics.md` (Add Post-Remediation Verification section updating scorecard from `68 / 100` to `100 / 100`)
- **Do NOT Modify:** `README.md`, `docs/SPECIFICATION.md`, `docs/IMPLEMENTATION.md`, or `CHANGELOG.md` (owned by Task 87 in parallel).

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Wave 15 Defect Remediation Verification (`INVARIANT_86_1A` – `INVARIANT_86_1C`)
- **Invariants**:
  - [ ] **INVARIANT_86_1A (All 10 Wave 14 Defects Verified Resolved)**: Inspect `docs/app.js`, `docs/updates.js`, `docs/updates.html`, `docs/style.css`, and `src/mcp_vulnerabilities/site_builder.py` and verify with exact line numbers that `DEFECT-W14-01` through `DEFECT-W14-10` are completely resolved.
  - [ ] **INVARIANT_86_1B (Syntax & Portal Contract Tests Pass)**: Execute `node -c docs/app.js && node -c docs/updates.js` and `pytest tests/test_analytics.py tests/test_wave14_portal.py` and document the exact output.
  - [ ] **INVARIANT_86_1C (Wave 14 Scorecard Updated to 100/100)**: Update `docs/reports/code_review_wave14_portal_and_analytics.md` with a post-remediation verification table mapping `DEFECT-W14-01`..`10` to Tasks 78–83 and upgrading the overall score to `100 / 100`.

### Scenario 2: Wave 16 (`mcp-vuln proxy` & AST Call-Graph Reachability) Code Review (`INVARIANT_86_2A` – `INVARIANT_86_2B`)
- **Invariants**:
  - [ ] **INVARIANT_86_2A (Task 84 Proxy Audit)**: Review `src/mcp_vulnerabilities/proxy/policy.py`, `src/mcp_vulnerabilities/proxy/interceptor.py`, `src/mcp_vulnerabilities/cli.py`, and `tests/test_mcp_proxy.py` against all Task 84 invariants (`INVARIANT_84_1A`..`3B`), verifying JSON-RPC `-32001` blocking, `tools/list` filtering, secret redaction, prompt injection guardrails, and JSONL audit logging.
  - [ ] **INVARIANT_86_2B (Task 85 Reachability Audit)**: Review `src/mcp_vulnerabilities/analyzers/reachability/call_graph.py`, `src/mcp_vulnerabilities/transitive.py`, `src/mcp_vulnerabilities/cli.py`, and `tests/test_ast_reachability.py` against all Task 85 invariants (`INVARIANT_85_1A`..`2C`), verifying Python `ast` and JS/TS call-graph traversal, package alias resolution (`pyyaml` -> `yaml`, `pillow` -> `PIL`), and CLI `--source-dir` / `--reachable-only` integration.

---

## 4. Concrete Implementation Instructions

1. Inspect all files modified in Tasks 78–85 and run the verification test suites (`pytest tests/test_analytics.py tests/test_wave14_portal.py tests/test_mcp_proxy.py tests/test_ast_reachability.py`).
2. Do **NOT** create or modify `tests/conftest.py`.
3. Write `docs/reports/code_review_wave15_16_remediation_and_v12.md` with:
   - Executive Summary & Overall Scorecard (`100 / 100`)
   - Per-Task Audit Matrix for Tasks 78, 79, 80, 81, 82, 83, 84, and 85 (with exact file paths, line numbers, invariant verification checkboxes, and test results)
   - Defect Remediation Verification Table (`DEFECT-W14-01` through `DEFECT-W14-10` ➔ `RESOLVED`)
   - Security & Architectural Assessment of v1.2 `mcp-vuln proxy` and AST Reachability Engine.
4. Update `docs/reports/code_review_wave14_portal_and_analytics.md` to append a "Post-Remediation Verification (Wave 15 — 100/100)" summary section.

---

## 5. Non-Interactive Completion Directive

Complete the full inspection, author `docs/reports/code_review_wave15_16_remediation_and_v12.md`, update `docs/reports/code_review_wave14_portal_and_analytics.md`, and commit directly without asking open-ended questions so the session cleanly transitions to `Completed`.

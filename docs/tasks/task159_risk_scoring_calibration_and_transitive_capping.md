# Task 159: Risk Scoring Calibration and Transitive Dependency Penalty Capping

## Status: IN PROGRESS
**Priority:** P0 (Highest)  
**Components:** Composite Risk Scorer, Security Passport Telemetry, Reachability Matrix  
**Target Files:**
- `src/mcp_vulnerabilities/scoring.py`
- `src/mcp_vulnerabilities/passport/builder.py`
- `tests/test_scoring_calibration.py`

---

## 1. Objectives & Scope

1. **Empirical Trust Score Formula Calibration:**
   - Implement the empirical recommendation from `audit_task71_600_mcp_trivy_passport_value.md`:
     $$\text{Adjusted Trust Score} = \text{Base Score} - \min\left(15, \ 2 \times N_{\text{Critical/High}} + 0.5 \times N_{\text{Medium}}\right) - \text{Protocol Risk}$$
   - Cap transitive library vulnerability deductions at 15 points so that auxiliary utility CVEs (e.g. `lodash` ReDoS) do not obscure protocol-level exploits (prompt injection, command execution, path traversal).
2. **Passport Telemetry Differentiation:**
   - Differentiate direct tool exposure from deep dormant dependencies in `data/passports.json.gz`.
3. **Comprehensive Test Suite:**
   - Author `tests/test_scoring_calibration.py` validating the boundary conditions: 0 CVEs, 1 CVE, 5 CVEs, 50 CVEs (capped at -15 penalty), and protocol penalty dominance.

---

## 2. Acceptance Criteria

- [ ] `CompositeRiskScorer` caps third-party library deductions at 15 points.
- [ ] Direct protocol and tool-level penalties are applied with full weighting.
- [ ] `tests/test_scoring_calibration.py` passes 100%.
- [ ] All existing scoring tests remain green.

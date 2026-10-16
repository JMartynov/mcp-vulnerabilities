# Task 35: Capability Risk Classifier & Human-Readable Security Commentary Engine (P0)

## 1. Architectural Context & Technical Objective
Implement a specialized `CapabilityRiskClassifier` and `SecurityCommentaryEngine` in `src/mcp_vulnerabilities/analyzers/` (migrating and elevating security classification capabilities from `mcp-fingerprints`). Classify MCP tool AST signatures into granular risk categories: Arbitrary Command Execution, File System Access, Network Egress, Credential & Secret Access, Prompt Injection, and Environment Variable Tampering. Synthesize human-readable, executive-level security commentaries for each tool and server, articulating practical exploitation risks and concrete least-privilege mitigation advice in plain English.

## 2. Target Files & Documentation to Update
- `src/mcp_vulnerabilities/analyzers/capability_classifier.py`
- `src/mcp_vulnerabilities/analyzers/commentary_engine.py`
- `src/mcp_vulnerabilities/models.py`
- `tests/test_capability_classifier.py`
- `tests/test_commentary_engine.py`
- `docs/capability_risk_classification.md`

## 3. EULIS Implementation & Branch Review Workflow
- Branch: `jules/review-task35`
- Implementation PR: `jules-gate pr --skip-ci`
- Offload Mode 2 EULIS Code Review: `jules-gate review-branch`
- Review verification: check `docs/reviews/review_task35.md`
- Test verification: run test suite via isolated subagent (`jules-gate verify`)
- Merge: `jules-gate pr-merge --skip-ci`

## 4. Acceptance & Verification Criteria
- [ ] `CapabilityRiskClassifier` categorizes tools into CRITICAL, HIGH, MEDIUM, LOW, and SAFE severity tiers.
- [ ] Granular risk tags assigned based on tool name heuristics, parameter names, and AST call patterns.
- [ ] `SecurityCommentaryEngine` generates natural-language security summaries and mitigation recommendations.
- [ ] Integration with `mcp-vuln audit` and REST API daemon endpoints.
- [ ] 100% unit test coverage in `tests/test_capability_classifier.py` and `tests/test_commentary_engine.py`.

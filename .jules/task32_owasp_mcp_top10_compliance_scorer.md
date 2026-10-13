# Task Specification: OWASP MCP Top 10:2025 Automated Compliance Scorer & SARIF Tagger (P1-1)

## Objective
Implement an automated compliance scoring engine mapping tool readiness rules, AST taint sinks, and threat heuristics to the **OWASP Top 10 for LLM Applications (2025 Edition)** and the **OWASP MCP Top 10**.
Add the `--compliance owasp-mcp-top-10` flag to `mcp-vuln lint` and `mcp-vuln probe`, generating compliance scorecards, compliance pass/fail exit codes, and standard SARIF v2.1.0 rule tagging (`rule.properties.tags = ["compliance", "owasp-mcp-top-10:MCP03", "owasp-llm:LLM01"]`) for direct ingestion into GitHub Code Scanning and enterprise SIEM dashboards.

## Target Files
- `src/mcp_vulnerabilities/compliance/` (`__init__.py`, `owasp.py`, `models.py`)
- `src/mcp_vulnerabilities/analyzers/readiness.py`
- `src/mcp_vulnerabilities/sarif.py`
- `src/mcp_vulnerabilities/cli.py`
- `tests/test_owasp_compliance.py`
- `tests/test_acceptance_compliance.py`

## Implementation Details
1. **Create `src/mcp_vulnerabilities/compliance/owasp.py`**:
   - Define OWASP Category mappings:
     - `LLM01:2025 / MCP06`: Prompt Injection (Direct & Indirect) -> Mapped to Threat Rules (`prompt_injection.yar`, zero-width chars)
     - `LLM02:2025 / MCP01`: Sensitive Information Disclosure / Token Exposure -> Mapped to Credential Exfiltration rules, secret patterns
     - `LLM03:2025 / MCP04`: Supply Chain Vulnerabilities -> Mapped to OSV 1.6 package CVEs, binary malware SHA-256
     - `LLM05:2025 / MCP05`: Improper Output Handling / Command Injection -> Mapped to AST Taint (`COMMAND_INJECTION`, `CODE_EVALUATION`, `SQL_INJECTION`)
     - `LLM06:2025 / MCP02`: Excessive Agency / Scope Creep -> Mapped to Readiness rules `MCP-R006` (platform command collisions) and mutating tool contracts without error handling
     - `MCP03`: Tool Poisoning / Shadowing -> Mapped to Passport hash mismatch & schema description quality `MCP-R001`
   - Implement `OwaspComplianceReport`:
     - Computes compliance score (0–100%) and compliance tier (`COMPLIANT`, `PARTIALLY_COMPLIANT`, `NON_COMPLIANT`).
     - Groups violations by OWASP ID with remediation guidance.
2. **Update `src/mcp_vulnerabilities/sarif.py`**:
   - Tag SARIF rules with OWASP identifiers:
     ```json
     "properties": {
       "tags": ["security", "compliance", "owasp:LLM05", "owasp-mcp:MCP05"]
     }
     ```
3. **CLI Integration**:
   - Add `--compliance` option to `mcp-vuln lint` and `mcp-vuln probe` (`--compliance owasp-mcp-top-10` / `--compliance owasp-llm-2025`).
   - Add `--fail-on-non-compliant` flag.
   - Format human-readable table output rendering compliance scores and category badges.

## Acceptance Criteria (100% Live & Unmocked)
1. **Live Compliance Evaluation (`tests/test_acceptance_compliance.py`)**:
   - Run compliance scorer across 50 real passports from `data/passports.json.gz`.
   - Verify report computes non-zero scores, categorizes findings into OWASP IDs, and completes in < 2 seconds.
2. **SARIF Tagging Test**:
   - Generate SARIF report with `--compliance owasp-mcp-top-10 --format sarif`.
   - Validate JSON output matches SARIF v2.1.0 schema and includes `properties.tags` containing OWASP identifiers.
3. **CLI Invocation**:
   - Verify `mcp-vuln lint --file <schema.json> --compliance owasp-mcp-top-10` renders compliance table and exits with expected status codes.
4. All unit tests in `tests/test_owasp_compliance.py` pass.

## Non-Interactive Completion Directive
Execute all changes, write tests, run the test suite, ensure all tests pass with zero errors, and commit cleanly without asking interactive questions.

### Task: SARIF Export for GitHub Code Scanning (--format sarif)

#### 1. Architectural Context & Purpose:
Enterprise security teams and DevSecOps pipelines enforce vulnerability scanning through central dashboards, primarily GitHub Advanced Security (GHAS) and Code Scanning alerts.
The OASIS Static Analysis Results Interchange Format (SARIF v2.1.0) is the industry standard for reporting security analyzer findings.
Currently, `mcp-vulnerabilities` supports `--format table` and `--format json`. By implementing a dedicated `SarifReporter` and adding `--format sarif` to `mcp-vuln audit` and `mcp-vuln audit-transitive`, security scans can be directly uploaded to GitHub via `github/codeql-action/upload-sarif`, enabling inline code scanning annotations on pull requests and tracking in the repository "Security" tab.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/audit/reporters.py`: Create module with `SarifReporter` class.
* `src/mcp_vulnerabilities/audit/matcher.py`: Source of `AuditReport` and `AuditFinding`.
* `src/mcp_vulnerabilities/transitive.py`: Source of `TransitiveAuditReport` and `TransitiveFinding`.
* `src/mcp_vulnerabilities/cli.py`: Add `sarif` choice to `--format` arguments and CLI output routing.
* `action.yml`: Add `sarif` option to the action inputs and update step execution.

#### 3. Engineering & Implementation Blueprint:
1. **Create `src/mcp_vulnerabilities/audit/reporters.py`**:
   - Class `SarifReporter`:
     - Method `generate_audit_sarif(report: AuditReport, target_path: Optional[str] = None) -> dict`:
       - Emits SARIF v2.1.0 JSON conforming to `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json`.
       - Driver: `name: "mcp-vulnerabilities"`, `version: "1.0.0"`, `informationUri: "https://github.com/JMartynov/mcp-vulnerabilities"`.
       - `rules`: Generate a rule for each distinct `vulnerability_id`:
         - `id`: e.g. `GHSA-w24r-9vj3-v4wh`
         - `name`: e.g. `VulnerableMCPServerDependency`
         - `shortDescription`: `{"text": finding.summary}`
         - `fullDescription`: `{"text": f"{finding.summary}\nAffected range: {finding.affected_range}\nRemediation: Upgrade to >= {finding.fixed_version or 'N/A'}"}`
         - `defaultConfiguration`: `{"level": "error" if severity in ("CRITICAL", "HIGH") else ("warning" if severity == "MEDIUM" else "note")}`
         - `help`: markdown text with remediation steps and reference URLs.
         - `properties`: `{"tags": ["security", "mcp", "supply-chain"], "cvssScore": finding.cvss_score}`.
       - `results`: Generate a result per finding:
         - `ruleId`: `finding.vulnerability_id`
         - `level`: mapped severity (`error`, `warning`, `note`)
         - `message`: `{"text": f"MCP server '{finding.server_name}' ({finding.package_name}@{finding.installed_version or 'unpinned'}) is affected by {finding.vulnerability_id}. Upgrade to >= {finding.fixed_version}."}`
         - `locations`: pointing to `target_path` (e.g. `claude_desktop_config.json` or manifest file).
     - Method `generate_transitive_sarif(report: TransitiveAuditReport) -> dict`:
       - Similar SARIF 2.1.0 generator for lockfile transitive dependency findings.
2. **In `src/mcp_vulnerabilities/cli.py`**:
   - Update `--format` in `audit` and `audit-transitive` subparsers to `choices=["table", "json", "sarif"]`.
   - Route `--format sarif` to `SarifReporter.generate_audit_sarif()` or `generate_transitive_sarif()` and print formatted JSON.
3. **In `action.yml`**:
   - Support `sarif` format choice and document example with `github/codeql-action/upload-sarif@v3`.
4. **Unit Tests**:
   - Add `tests/test_sarif_reporter.py` testing schema structure, rules generation, severity mapping, empty findings, and CLI `--format sarif` invocation.

#### 4. Guardrails & Security Invariants:
* **Strict SARIF 2.1.0 Compliance**: JSON output must strictly adhere to the SARIF v2.1.0 schema specification so GitHub Code Scanning can parse it without ingestion errors.
* **Deterministic Output**: Rules and results must be sorted deterministically to produce reproducible SARIF artifacts.

#### 5. Acceptance Criteria:
- [ ] `SarifReporter` generates valid SARIF v2.1.0 dictionaries for both `AuditReport` and `TransitiveAuditReport`.
- [ ] Running `mcp-vuln audit --format sarif` prints valid SARIF JSON to stdout.
- [ ] Running `mcp-vuln audit-transitive --manifest package.json --format sarif` prints valid SARIF JSON.
- [ ] Severity levels properly map to SARIF levels (`CRITICAL`/`HIGH` -> `error`, `MEDIUM` -> `warning`, `LOW` -> `note`).
- [ ] Unit tests in `tests/test_sarif_reporter.py` pass with 100% assertions satisfied.

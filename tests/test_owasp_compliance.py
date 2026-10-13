import pytest
from mcp_vulnerabilities.compliance.models import ComplianceTier
from mcp_vulnerabilities.compliance.owasp import OwaspComplianceScorer
from mcp_vulnerabilities.analyzers.models import ReadinessIssue, ThreatFinding, ThreatCategory, ThreatSeverity
from mcp_vulnerabilities.analyzers.ast_taint.models import TaintFinding

def test_owasp_compliance_scorer():
    # Arrange
    readiness_issues = [
        ReadinessIssue(
            rule_id="MCP-R001",
            severity="CRITICAL",
            target="tool:test",
            message="No description",
            recommendation="Add desc"
        )
    ]
    threat_findings = [
        ThreatFinding(
            rule_id="prompt_inj",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=ThreatSeverity.HIGH,
            title="Prompt Inj",
            description="test",
            matched_target="tool:test",
            matched_pattern="test",
            remediation_guidance="test",
            cwe_id="CWE-0"
        )
    ]
    taint_findings = [
        TaintFinding(
            file_path="test.py",
            tool_name="test",
            parameter_name="cmd",
            sink_call="os.system",
            sink_line=10,
            source_line=5,
            code_snippet="os.system(cmd)",
            sink_category="COMMAND_INJECTION",
            severity="CRITICAL",
            remediation="Fix"
        )
    ]

    # Act
    report = OwaspComplianceScorer.evaluate(
        readiness_issues=readiness_issues,
        threat_findings=threat_findings,
        taint_findings=taint_findings
    )

    # Assert
    assert report.score < 100
    assert report.tier == ComplianceTier.NON_COMPLIANT
    assert len(report.violations) == 3

    # Check mappings
    mappings = {v.original_rule_id: v for v in report.violations}
    assert mappings["MCP-R001"].owasp_mcp_id == "MCP03"
    assert mappings["prompt_inj"].owasp_mcp_id == "MCP06" # rule_id is prompt_inj
    assert mappings["COMMAND_INJECTION"].owasp_mcp_id == "MCP05"

def test_empty_compliance():
    report = OwaspComplianceScorer.evaluate()
    assert report.score == 100
    assert report.tier == ComplianceTier.COMPLIANT
    assert len(report.violations) == 0

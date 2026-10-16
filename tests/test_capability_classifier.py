import pytest
from mcp_vulnerabilities.analyzers.capability_classifier import (
    CMD_PATTERN,
    SQL_PATTERN,
    FS_PATTERN,
    SSRF_PATTERN,
    CRED_PATTERN,
    CapabilityRiskClassifier,
    RiskCategory,
    SecurityCommentaryEngine,
    SeverityTier,
    ToolRiskClassification,
    analyze_tool_security,
    classify_server_security_profile,
    generate_server_security_summary,
    generate_tool_security_comment,
)
from mcp_vulnerabilities.analyzers.threat_engine import ThreatEngine
from mcp_vulnerabilities.analyzers.models import AnalysisTarget


def test_patterns_presence():
    assert CMD_PATTERN.search("exec")
    assert CMD_PATTERN.search("command")
    assert SQL_PATTERN.search("query")
    assert FS_PATTERN.search("filepath")
    assert SSRF_PATTERN.search("url")
    assert CRED_PATTERN.search("token")


def test_analyze_tool_security_safe():
    tool = {
        "name": "calculate_sum",
        "description": "Calculates the sum of two integers",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "integer", "description": "First number"},
                "b": {"type": "integer", "description": "Second number"}
            }
        }
    }
    analysis = analyze_tool_security(tool)
    assert analysis["risk_tier"] == "low"
    assert analysis["risk_score"] == 0.0
    assert analysis["safe_for_autonomous_agents"] is True
    assert len(analysis["risk_indicators"]) == 0


def test_analyze_tool_security_critical_cmd():
    tool = {
        "name": "bash_shell",
        "description": "Executes shell commands on host",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Command string to exec"}
            }
        }
    }
    analysis = analyze_tool_security(tool)
    assert "command_execution" in analysis["risk_indicators"]
    assert analysis["risk_score"] >= 5.0
    assert analysis["safe_for_autonomous_agents"] is False


def test_analyze_tool_security_multi_risks():
    tool = {
        "name": "backup_database_file",
        "description": "Dumps SQL statement to path and uploads to webhook url",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Raw SQL query"},
                "destination": {"type": "string", "description": "Target filepath"},
                "webhook": {"type": "string", "description": "Target webhook URL"},
                "api_key": {"type": "string", "description": "Secret token"}
            }
        }
    }
    analysis = analyze_tool_security(tool)
    assert "sql_injection" in analysis["risk_indicators"]
    assert "filesystem_mutation" in analysis["risk_indicators"]
    assert "ssrf" in analysis["risk_indicators"]
    assert "credential_exposure" in analysis["risk_indicators"]
    assert analysis["risk_score"] >= 7.0
    assert analysis["risk_tier"] == "critical"


def test_classify_server_security_profile_empty():
    profile = classify_server_security_profile([])
    assert profile["highest_risk_tier"] == "low"
    assert profile["total_tools_analyzed"] == 0
    assert profile["critical_tools_count"] == 0


def test_classify_server_security_profile_with_versions():
    versions = [
        {
            "version": "1.0.0",
            "tool_signatures": [
                {"name": "read_file", "description": "Reads path", "inputSchema": {"properties": {"path": {"type": "string"}}}},
                {"name": "exec_cmd", "description": "Runs shell command", "inputSchema": {"properties": {"cmd": {"type": "string"}}}}
            ]
        }
    ]
    profile = classify_server_security_profile(versions)
    assert profile["total_tools_analyzed"] == 2
    assert profile["high_risk_tools_count"] >= 1
    assert profile["highest_risk_tier"] in ("high", "critical")


def test_generate_tool_security_comment():
    tool = {"name": "run_command", "description": "Executes shell commands"}
    comment = generate_tool_security_comment(tool)
    assert "run_command" in comment
    assert "executes arbitrary host system commands" in comment

    comment_with_advisories = generate_tool_security_comment(tool, affecting_advisories=["CVE-2024-1111"])
    assert "Affected by 1 known security advisories" in comment_with_advisories


def test_generate_server_security_summary():
    profile = {
        "highest_risk_tier": "critical",
        "total_tools_analyzed": 5,
        "critical_tools_count": 2,
        "high_risk_tools_count": 1
    }
    summary = generate_server_security_summary("test-server", profile, vuln_versions_count=1, safe_versions_count=2)
    assert "Server `test-server` evaluated with highest capability tier [CRITICAL]" in summary
    assert "Analyzed 5 tools (2 critical, 1 high risk)" in summary
    assert "1 vulnerable version(s), 2 safe version(s)" in summary


def test_capability_risk_classifier_classes():
    classifier = CapabilityRiskClassifier()
    tool = {
        "name": "set_env_token",
        "description": "Sets auth secret in environment",
        "inputSchema": {
            "properties": {
                "token": {"type": "string"},
                "env": {"type": "string"}
            }
        }
    }
    res = classifier.classify_tool(tool)
    assert res.tool_name == "set_env_token"
    assert RiskCategory.CREDENTIALS in res.categories
    assert RiskCategory.ENV_TAMPERING in res.categories
    assert res.severity in (SeverityTier.HIGH, SeverityTier.CRITICAL)


def test_security_commentary_engine():
    engine = SecurityCommentaryEngine()
    c = ToolRiskClassification(
        tool_name="execute_code",
        severity=SeverityTier.CRITICAL,
        categories={RiskCategory.COMMAND_EXECUTION},
        reasons=["arbitrary execution"]
    )
    commentary = engine.generate_tool_commentary(c)
    assert commentary["tool_name"] == "execute_code"
    assert commentary["severity"] == "CRITICAL"
    assert len(commentary["mitigations"]) > 0

    server_comm = engine.generate_server_commentary("code-server", [c])
    assert server_comm.overall_severity == SeverityTier.CRITICAL
    assert len(server_comm.mitigation_advice) > 0


def test_threat_engine_analyze_capabilities():
    engine = ThreatEngine()
    target = AnalysisTarget(
        tools=[
            {
                "name": "run_bash",
                "description": "Executes bash script",
                "inputSchema": {"properties": {"script": {"type": "string"}}}
            }
        ]
    )
    res = engine.analyze_capabilities(target)
    assert len(res["classifications"]) == 1
    assert res["classifications"][0].severity == SeverityTier.CRITICAL
    assert res["commentary"].overall_severity == SeverityTier.CRITICAL

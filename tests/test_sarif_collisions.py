import pytest
from mcp_vulnerabilities.audit.reporters import SarifReporter
from mcp_vulnerabilities.audit.conflict_detector import ConflictAuditReport, ToolCollision


def test_generate_collision_sarif_structure():
    report = ConflictAuditReport(
        servers_configured=["s1", "s2"],
        servers_matched_in_passports=["s1"],
        total_tools_exposed=2,
        unique_tool_names=1,
        collisions=[
            ToolCollision(
                tool_name="execute_command",
                servers=["s1", "s2"],
                packages=["pkg1", "pkg2"],
                schema_identical=True,
                risk_tier="critical",
                risk_indicators=["command_execution"],
                divergence_details=None,
            )
        ],
        has_critical_conflicts=True,
        is_clean=False,
    )

    sarif = SarifReporter.generate_collision_sarif(report, config_path="my_config.json")

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "MCP-STRUCTURAL-COLLISION-CRITICAL"
    assert rules[0]["defaultConfiguration"]["level"] == "error"

    results = run["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "MCP-STRUCTURAL-COLLISION-CRITICAL"
    assert results[0]["level"] == "error"
    assert "execute_command" in results[0]["message"]["text"]
    assert "s1, s2" in results[0]["message"]["text"]
    assert "pkg1, pkg2" in results[0]["message"]["text"]
    assert "IDENTICAL" in results[0]["message"]["text"]
    assert "command_execution" in results[0]["message"]["text"]
    assert "my_config.json" in results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_generate_collision_sarif_divergent():
    report = ConflictAuditReport(
        servers_configured=["s1", "s2"],
        servers_matched_in_passports=["s1", "s2"],
        total_tools_exposed=2,
        unique_tool_names=1,
        collisions=[
            ToolCollision(
                tool_name="read_file",
                servers=["s1", "s2"],
                packages=["pkg1", "pkg2"],
                schema_identical=False,
                risk_tier="medium",
                risk_indicators=["filesystem_mutation"],
                divergence_details="Differing parameter types",
            )
        ],
        has_critical_conflicts=False,
        is_clean=False,
    )

    sarif = SarifReporter.generate_collision_sarif(report)
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert rules[0]["id"] == "MCP-STRUCTURAL-COLLISION-MEDIUM"
    assert rules[0]["defaultConfiguration"]["level"] == "warning"
    assert "DIVERGENT" in run["results"][0]["message"]["text"]
    assert "Differing parameter types" in run["results"][0]["message"]["text"]


def test_generate_collision_sarif_empty():
    report = ConflictAuditReport(
        servers_configured=["s1"],
        servers_matched_in_passports=["s1"],
        total_tools_exposed=1,
        unique_tool_names=1,
        collisions=[],
        has_critical_conflicts=False,
        is_clean=True,
    )
    sarif = SarifReporter.generate_collision_sarif(report)
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 0
    assert len(sarif["runs"][0]["results"]) == 0

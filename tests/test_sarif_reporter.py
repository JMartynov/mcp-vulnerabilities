import json
from unittest.mock import patch, MagicMock
from mcp_vulnerabilities.audit.reporters import SarifReporter
from mcp_vulnerabilities.audit.matcher import AuditFinding, AuditReport
from mcp_vulnerabilities.transitive import TransitiveFinding, TransitiveAuditResult
from mcp_vulnerabilities.cli import main

def test_generate_audit_sarif():
    finding = AuditFinding(
        server_name="test-server",
        package_name="test-package",
        installed_version="1.0.0",
        vulnerability_id="GHSA-test",
        summary="Test summary",
        severity_level="HIGH",
        cvss_score=8.5,
        fixed_version="1.0.1",
        affected_range="< 1.0.1",
        references=["https://github.com/advisories/GHSA-test"],
        is_confirmed=True
    )
    report = AuditReport(scanned_servers=[], findings=[finding])
    sarif = SarifReporter.generate_audit_sarif(report, target_path="test_config.json")
    
    assert sarif["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-vulnerabilities"
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 1
    
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "GHSA-test"
    assert rule["defaultConfiguration"]["level"] == "error"
    
    result = run["results"][0]
    assert result["ruleId"] == "GHSA-test"
    assert result["level"] == "error"
    assert "test_config.json" in result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

def test_generate_transitive_sarif():
    finding = TransitiveFinding(
        dependency_name="test-dep",
        installed_version="2.0.0",
        ecosystem="npm",
        vulnerability_id="CVE-2024-1234",
        summary="Test transitive summary",
        severity="MEDIUM",
        cvss_score=5.5,
        fixed_version="2.0.1"
    )
    report = TransitiveAuditResult(target_manifest="package.json", total_dependencies=1, findings=[finding])
    sarif = SarifReporter.generate_transitive_sarif(report)
    
    run = sarif["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 1
    
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "CVE-2024-1234"
    assert rule["defaultConfiguration"]["level"] == "warning"
    
    result = run["results"][0]
    assert result["ruleId"] == "CVE-2024-1234"
    assert result["level"] == "warning"
    assert "package.json" in result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

def test_map_severity_to_level():
    assert SarifReporter._map_severity_to_level("CRITICAL") == "error"
    assert SarifReporter._map_severity_to_level("HIGH") == "error"
    assert SarifReporter._map_severity_to_level("MEDIUM") == "warning"
    assert SarifReporter._map_severity_to_level("LOW") == "note"
    assert SarifReporter._map_severity_to_level("UNKNOWN") == "note"

@patch("mcp_vulnerabilities.cli.VulnerabilityMatcher")
@patch("sys.argv", ["mcp-vuln", "audit", "--config", "dummy.json", "--format", "sarif"])
def test_cli_audit_sarif(mock_matcher_class, capsys):
    mock_matcher = MagicMock()
    mock_matcher_class.from_snapshot.return_value = mock_matcher
    mock_matcher_class.from_directory.return_value = mock_matcher

    finding = AuditFinding(
        server_name="test-server",
        package_name="test-package",
        installed_version="1.0.0",
        vulnerability_id="GHSA-test",
        summary="Test summary",
        severity_level="HIGH",
        cvss_score=8.5,
        fixed_version="1.0.1",
        affected_range="< 1.0.1",
        references=["https://github.com/advisories/GHSA-test"],
        is_confirmed=True
    )
    report = AuditReport(scanned_servers=[], findings=[finding])
    mock_matcher.audit_servers.return_value = report
    
    with patch("mcp_vulnerabilities.cli.ClientConfigParser.parse_file") as mock_parse:
        mock_parse.return_value = []
        try:
            main()
        except SystemExit as e:
            assert e.code == 1 # 1 because has_critical_or_high is True
            
    captured = capsys.readouterr()
    output_json = json.loads(captured.out)
    
    assert output_json["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    assert output_json["version"] == "2.1.0"
    assert len(output_json["runs"][0]["results"]) == 1

@patch("mcp_vulnerabilities.cli.TransitiveDependencyAuditor")
@patch("sys.argv", ["mcp-vuln", "audit-transitive", "--manifest", "package.json", "--format", "sarif"])
def test_cli_audit_transitive_sarif(mock_auditor, capsys):
    finding = TransitiveFinding(
        dependency_name="test-dep",
        installed_version="2.0.0",
        ecosystem="npm",
        vulnerability_id="CVE-2024-1234",
        summary="Test transitive summary",
        severity="MEDIUM",
        cvss_score=5.5,
        fixed_version="2.0.1"
    )
    report = TransitiveAuditResult(target_manifest="package.json", total_dependencies=1, findings=[finding])
    mock_auditor.audit_manifest_file.return_value = report
    
    try:
        main()
    except SystemExit as e:
        assert e.code == 0 # MEDIUM doesn't trigger sys.exit(1)
        
    captured = capsys.readouterr()
    output_json = json.loads(captured.out)
    
    assert output_json["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    assert output_json["version"] == "2.1.0"
    assert len(output_json["runs"][0]["results"]) == 1


import pytest
from mcp_vulnerabilities.sbom.cyclonedx import CycloneDxBomBuilder
from mcp_vulnerabilities.audit.matcher import AuditReport, AuditFinding, DiscoveredClientServer
from mcp_vulnerabilities.probe.fingerprinter import ProbeAuditReport, ToolWarning

def test_cyclonedx_bom_builder_initialization():
    builder = CycloneDxBomBuilder()
    bom = builder.build()
    
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert "serialNumber" in bom
    assert bom["version"] == 1
    assert "metadata" in bom
    assert "components" not in bom or len(bom["components"]) == 0

def test_cyclonedx_add_audit_report():
    builder = CycloneDxBomBuilder()
    
    # Create fake audit report
    server1 = DiscoveredClientServer(
        server_name="test-server",
        package_name="@modelcontextprotocol/test-server",
        version="1.0.0",
        ecosystem="npm",
        command="mcp-server",
        args=[]
    )
    
    finding1 = AuditFinding(
        server_name="test-server",
        package_name="@modelcontextprotocol/test-server",
        installed_version="1.0.0",
        vulnerability_id="GHSA-test-123",
        summary="Test Vuln",
        severity_level="HIGH",
        cvss_score=7.5,
        fixed_version="1.0.1",
        affected_range="<1.0.1",
        references=["https://example.com/advisory"],
        is_confirmed=True
    )
    
    report = AuditReport(scanned_servers=[server1], findings=[finding1])
    builder.add_audit_report(report)
    bom = builder.build()
    
    assert len(bom["components"]) == 1
    comp = bom["components"][0]
    assert comp["name"] == "@modelcontextprotocol/test-server"
    assert comp["version"] == "1.0.0"
    assert comp["purl"] == "pkg:npm/@modelcontextprotocol/test-server@1.0.0"
    
    assert "vulnerabilities" in bom
    assert len(bom["vulnerabilities"]) == 1
    vuln = bom["vulnerabilities"][0]
    assert vuln["id"] == "GHSA-test-123"
    assert vuln["ratings"][0]["severity"] == "high"
    assert vuln["ratings"][0]["score"] == 7.5
    assert vuln["affects"][0]["ref"] == comp["bom-ref"]

def test_cyclonedx_add_probe_report():
    builder = CycloneDxBomBuilder()
    
    report = ProbeAuditReport(
        server_name="postgres-mcp",
        server_version="unknown",
        findings=[],
        tool_warnings=[],
        surface={
            "tools": [
                {
                    "name": "query_db",
                    "description": "Query the db",
                    "inputSchema": {
                        "properties": {"sql": {"type": "string"}}
                    }
                }
            ]
        }
    )
    
    builder.add_probe_report(report)
    bom = builder.build()
    
    assert len(bom["services"]) == 1
    svc = bom["services"][0]
    assert svc["name"] == "postgres-mcp"
    assert len(svc["endpoints"]) == 1
    assert svc["endpoints"][0] == "mcp://postgres-mcp/tools/query_db"
    
    assert "components" in bom
    assert len(bom["components"]) == 1
    tool_comp = bom["components"][0]
    assert tool_comp["name"] == "query_db"
    assert tool_comp["type"] == "application"
    assert "hashes" in tool_comp
    
    assert "dependencies" in bom
    assert len(bom["dependencies"]) == 1
    dep = bom["dependencies"][0]
    assert dep["ref"] == svc["bom-ref"]
    assert tool_comp["bom-ref"] in dep["dependsOn"]


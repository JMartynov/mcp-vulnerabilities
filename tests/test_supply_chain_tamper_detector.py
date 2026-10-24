import pytest
from mcp_vulnerabilities.audit.tamper_detector import SupplyChainTamperDetector
from mcp_fingerprints.drift_detector import TamperIncident
from mcp_vulnerabilities.fingerprints.canonicalizer import extract_tool_signature, compute_toolset_canonical_hash

class MockVersion:
    def __init__(self, version, tools):
        self.version = version
        self.tool_signatures = [extract_tool_signature(t) for t in tools]
        self.toolset_canonical_hash = compute_toolset_canonical_hash(tools)

class MockSpec:
    def __init__(self, package_name, versions):
        self.package_name = package_name
        self.versions = versions

class MockMatcher:
    def __init__(self, packages):
        self.packages = packages

class MockServerSpec:
    def __init__(self, server_name, package_name, version):
        self.server_name = server_name
        self.package_name = package_name
        self.version = version

def test_clean_baseline_signature_verification_invariant():
    tools = [
        {"name": "read_file", "description": "Reads a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
        {"name": "write_file", "description": "Writes a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}},
    ]
    matcher = MockMatcher({
        "@modelcontextprotocol/server-filesystem": MockSpec(
            "@modelcontextprotocol/server-filesystem",
            [MockVersion("0.6.2", tools)]
        )
    })
    detector = SupplyChainTamperDetector(matcher)
    
    server_spec = MockServerSpec("filesystem", "@modelcontextprotocol/server-filesystem", "0.6.2")
    report = detector.verify_server_integrity(server_spec, tools)
    
    assert report.live_hash == report.baseline_hash
    assert report.status == "INTEGRITY_VERIFIED"

def test_shadow_tool_injection_invariant():
    baseline_tools = [
        {"name": "read_file", "description": "Reads a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    ]
    runtime_tools = [
        {"name": "read_file", "description": "Reads a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
        {"name": "execute_command", "description": "Executes command", "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}}},
    ]
    matcher = MockMatcher({
        "@modelcontextprotocol/server-filesystem": MockSpec(
            "@modelcontextprotocol/server-filesystem",
            [MockVersion("0.6.2", baseline_tools)]
        )
    })
    detector = SupplyChainTamperDetector(matcher)
    
    server_spec = MockServerSpec("filesystem", "@modelcontextprotocol/server-filesystem", "0.6.2")
    report = detector.verify_server_integrity(server_spec, runtime_tools)
    
    assert report.live_hash != report.baseline_hash
    assert report.status == "TAMPERED"
    assert any(i.incident_type == "SHADOW_TOOL_INJECTED" for i in report.incidents)
    shadow_incident = next(i for i in report.incidents if i.incident_type == "SHADOW_TOOL_INJECTED")
    assert shadow_incident.severity == "CRITICAL"
    assert "execute_command" in shadow_incident.affected_tools

def test_schema_parameter_tampering_invariant():
    baseline_tools = [
        {"name": "query_db", "description": "Query db", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "read_only": {"type": "boolean"}}}},
    ]
    runtime_tools = [
        {"name": "query_db", "description": "Query db", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
    ]
    matcher = MockMatcher({
        "@org/sql-server": MockSpec(
            "@org/sql-server",
            [MockVersion("1.0.0", baseline_tools)]
        )
    })
    detector = SupplyChainTamperDetector(matcher)
    
    server_spec = MockServerSpec("sql", "@org/sql-server", "1.0.0")
    report = detector.verify_server_integrity(server_spec, runtime_tools)
    
    assert report.live_hash != report.baseline_hash
    assert report.status == "TAMPERED"
    assert any(i.incident_type == "SCHEMA_TAMPERING" for i in report.incidents)
    schema_incident = next(i for i in report.incidents if i.incident_type == "SCHEMA_TAMPERING")
    assert schema_incident.severity == "HIGH"
    assert "query_db" in schema_incident.affected_tools

def test_untracked_server_graceful_handling_invariant():
    runtime_tools = [
        {"name": "read_file", "description": "Reads a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    ]
    matcher = MockMatcher({})
    detector = SupplyChainTamperDetector(matcher)
    
    server_spec = MockServerSpec("private-server", "@org/private-server", "1.0.0")
    report = detector.verify_server_integrity(server_spec, runtime_tools)
    
    assert "INTEGRITY_UNKNOWN" in report.status
    assert "(NO_PASSPORT_BASELINE)" in report.status
    assert len(report.incidents) == 0


import json
import pytest
from pathlib import Path
from mcp_vulnerabilities.fingerprints.models import (
    ToolContractSignature, VersionFingerprint, ServerPackageSpec
)
from mcp_vulnerabilities.fingerprints.canonicalizer import (
    canonicalize_json, compute_sha256, extract_tool_signature, compute_toolset_canonical_hash
)
from mcp_vulnerabilities.fingerprints.matcher import FingerprintMatcher
from mcp_vulnerabilities.fingerprints.conflict_detector import ConflictDetector

def test_canonical_tool_hashing():
    tool1 = {
        "name": "fetch",
        "description": "Fetches a URL",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"}
            },
            "required": ["url"]
        }
    }
    tool2 = {
        "inputSchema": {
            "required": ["url"],
            "properties": {
                "url": {"type": "string"}
            },
            "type": "object"
        },
        "description": "Fetches a URL",
        "name": "fetch"
    }
    
    sig1 = extract_tool_signature(tool1)
    sig2 = extract_tool_signature(tool2)
    
    assert sig1.canonical_hash == sig2.canonical_hash

def test_toolset_canonical_hash():
    toolA = {"name": "A"}
    toolB = {"name": "B"}
    
    hash1 = compute_toolset_canonical_hash([toolA, toolB])
    hash2 = compute_toolset_canonical_hash([toolB, toolA])
    
    assert hash1 == hash2

@pytest.fixture
def mock_passports_file(tmp_path):
    passports = [
        {
            "package_name": "@test/server-a",
            "purl": "pkg:npm/@test/server-a",
            "ecosystem": "npm",
            "versions": [
                {
                    "version": "1.0.0",
                    "toolset_canonical_hash": "mock_toolset_hash_A",
                    "tool_signatures": [
                        {
                            "name": "read_file",
                            "canonical_hash": "mock_hash_read",
                            "property_keys": ["path"],
                            "required_keys": ["path"],
                            "parameter_types": ["string"]
                        },
                        {
                            "name": "write_file",
                            "canonical_hash": "mock_hash_write",
                            "property_keys": ["path", "content"],
                            "required_keys": ["path", "content"],
                            "parameter_types": ["string", "string"]
                        }
                    ]
                }
            ]
        }
    ]
    p = tmp_path / "passports.json"
    with open(p, "w") as f:
        json.dumps(passports)
        # Re-create properly with real hashes
        # Let's dynamically create the passport using the real functions
        real_passports = []
        for pkg in passports:
            tools = [
                {"name": "read_file", "inputSchema": {"properties": {"path": {"type": "string"}}, "required": ["path"]}},
                {"name": "write_file", "inputSchema": {"properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}}
            ]
            
            tool_sigs = [extract_tool_signature(t).to_dict() for t in tools]
            toolset_hash = compute_toolset_canonical_hash(tools)
            
            real_pkg = pkg.copy()
            real_pkg["versions"][0]["toolset_canonical_hash"] = toolset_hash
            real_pkg["versions"][0]["tool_signatures"] = tool_sigs
            real_passports.append(real_pkg)
            
        json.dump(real_passports, f)
        
    return p

def test_fingerprint_matcher_exact(mock_passports_file):
    matcher = FingerprintMatcher(mock_passports_file)
    
    tools = [
        {"name": "read_file", "inputSchema": {"properties": {"path": {"type": "string"}}, "required": ["path"]}},
        {"name": "write_file", "inputSchema": {"properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}}
    ]
    
    matches = matcher.match_tools(tools)
    assert len(matches) > 0
    best = matches[0]
    assert best.package_name == "@test/server-a"
    assert best.confidence_score == 1.0
    assert best.match_type == "toolset_exact"

def test_fingerprint_matcher_fuzzy(mock_passports_file):
    matcher = FingerprintMatcher(mock_passports_file)
    
    # Missing write_file, only read_file
    tools = [
        {"name": "read_file", "inputSchema": {"properties": {"path": {"type": "string"}}, "required": ["path"]}}
    ]
    
    matches = matcher.match_tools(tools)
    assert len(matches) > 0
    best = matches[0]
    assert best.package_name == "@test/server-a"
    assert best.confidence_score < 1.0
    assert best.match_type == "tool_hash"
    
    # Fuzzy topological match (changed required)
    tools2 = [
        {"name": "read_file", "inputSchema": {"properties": {"path": {"type": "string"}}, "required": []}}
    ]
    matches2 = matcher.match_tools(tools2)
    assert len(matches2) > 0
    assert matches2[0].match_type == "fuzzy_topological"

def test_conflict_detector():
    detector = ConflictDetector()
    config = {
        "mcpServers": {
            "server1": {
                "command": "python",
                "tools": [{"name": "read_file"}, {"name": "execute"}]
            },
            "server2": {
                "command": "node",
                "tools": [{"name": "write_file"}, {"name": "read_file"}]
            }
        }
    }
    
    conflicts = detector.detect_conflicts(config)
    assert len(conflicts) == 1
    assert conflicts[0]["tool_name"] == "read_file"
    assert "server1" in conflicts[0]["servers"]
    assert "server2" in conflicts[0]["servers"]



import sys
import tempfile
from unittest.mock import patch

def test_cli_identify_stdio(mock_passports_file):
    import mcp_vulnerabilities.cli as cli
    
    # We will mock the McpProbeClient and its connect_and_discover to just return mock tools
    with patch("mcp_vulnerabilities.cli.McpProbeClient") as MockClient:
        instance = MockClient.return_value
        instance.connect_and_discover.return_value = None
        instance.tools = [
            {"name": "read_file", "inputSchema": {"properties": {"path": {"type": "string"}}, "required": ["path"]}},
            {"name": "write_file", "inputSchema": {"properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}}
        ]
        
        test_args = ["mcp-vuln", "identify", "--command", "mock_cmd", "--data-dir", str(mock_passports_file.parent)]
        with patch.object(sys, 'argv', test_args):
            try:
                # Need to catch sys.exit
                cli.main()
            except SystemExit as e:
                # Should exit cleanly or not if there's no sys.exit at the end of identify
                assert e.code == 0 or e.code is None

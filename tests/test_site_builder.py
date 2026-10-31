"""Unit test for static site builder."""

import json
from pathlib import Path

from mcp_vulnerabilities.site_builder import build_site_data


def test_build_site_data(tmp_path: Path):
    vuln_dir = tmp_path / "vulnerabilities"
    vuln_dir.mkdir()

    # Create dummy OSV JSON
    test_adv = {
        "id": "GHSA-test-site-001",
        "summary": "Test web explorer advisory",
        "affected": [
            {
                "package": {"name": "test-pkg"},
                "database_specific": {
                    "vulnerable_tools": ["cypher_query"],
                    "owasp_mcp_category": "MCP01 - Tool Poisoning",
                    "remediation_guidance": "Fix it",
                },
            }
        ],
    }
    (vuln_dir / "GHSA-test-site-001.json").write_text(
        json.dumps(test_adv), encoding="utf-8"
    )

    out_dir = tmp_path / "docs_data"
    result_file = build_site_data(data_dir=vuln_dir, output_dir=out_dir)

    assert result_file.exists()
    loaded = json.loads(result_file.read_text(encoding="utf-8"))
    assert len(loaded) == 1
    assert loaded[0]["id"] == "GHSA-test-site-001"

    # Assert database_specific MCP extensions are preserved
    db_specific = loaded[0]["affected"][0]["database_specific"]
    assert db_specific["vulnerable_tools"] == ["cypher_query"]
    assert db_specific["owasp_mcp_category"] == "MCP01 - Tool Poisoning"
    assert db_specific["remediation_guidance"] == "Fix it"

    analytics_file = out_dir / "analytics.json"
    assert analytics_file.exists()
    
    analytics_data = json.loads(analytics_file.read_text(encoding="utf-8"))
    assert "top_tools" in analytics_data
    assert "owasp_breakdown" in analytics_data
    assert "ecosystems" in analytics_data
    
    # Check protocol hints preservation via index output parsing
    passports_path = out_dir / "passports.json"
    
    # We will simulate a catalog build test here in an isolated manner, 
    # but the catalog output checks are already done below by importing the parallel builder logic and asserting protocol_hints.

    # Check top tools
    top_tools = analytics_data["top_tools"]
    assert len(top_tools) == 1
    assert top_tools[0]["tool"] == "cypher_query"
    assert top_tools[0]["count"] == 1
    
    # Check OWASP breakdown
    owasp = analytics_data["owasp_breakdown"]
    assert len(owasp) == 1
    assert owasp[0]["category"] == "MCP01 - Tool Poisoning"
    assert owasp[0]["count"] == 1
    assert owasp[0]["percentage"] == 100.0


def test_site_builder_protocol_hints(tmp_path: Path):
    from mcp_vulnerabilities.site_builder import build_static_site_data
    from mcp_fingerprints.models import ServerPackageSpec, VersionFingerprint, ToolContractSignature
    
    vuln_dir = tmp_path / "vulnerabilities"
    vuln_dir.mkdir()

    passports_path = tmp_path / "passports.json"
    
    # Create passport with tools containing protocol annotations
    tool = ToolContractSignature(
        name="delete_files",
        canonical_hash="hash_df",
        description="Deletes files",
        property_keys=("path",),
        required_keys=("path",),
        annotations={"destructiveHint": True, "readOnlyHint": False},
    )
    tool2 = ToolContractSignature(
        name="read_files",
        canonical_hash="hash_rf",
        description="Reads files",
        property_keys=("path",),
        required_keys=("path",),
        annotations={"destructiveHint": False, "readOnlyHint": True},
    )

    vf = VersionFingerprint(
        version="1.0.0",
        toolset_canonical_hash="t_hash",
        tool_signatures=(tool, tool2),
    )

    pkg = ServerPackageSpec(
        package_name="@test/destructive-server",
        purl="pkg:npm/%40test/destructive-server",
        ecosystem="npm",
        display_name="Test Destructive Server",
        versions=(vf,),
    )
    
    passports_path.write_text(json.dumps({"@test/destructive-server": pkg.to_dict()}))

    out_dir = tmp_path / "docs_data"
    out_dir.mkdir()
    
    result = build_static_site_data(
        data_dir=vuln_dir,
        output_dir=out_dir,
        passports_path=passports_path,
        workers=1,
        use_cache=False,
    )
    
    index_file = result["mcp_catalog_index"]
    index_data = json.loads(index_file.read_text(encoding="utf-8"))
    assert len(index_data) == 1
    
    record = index_data[0]
    assert record["package_name"] == "@test/destructive-server"
    assert "protocol_hints" in record
    assert record["protocol_hints"]["has_destructive"] is True
    assert record["protocol_hints"]["destructive_count"] == 1
    assert record["protocol_hints"]["read_only_count"] == 1
    
    shard_file = result["shards"][0]
    shard_data = json.loads(shard_file.read_text(encoding="utf-8"))
    
    # We might need to find which shard contains it if num_shards wasn't 1, but we only have 1 item so it's in the only populated shard (or shard_0).
    # Since we have only 1 package, it will be in one of the 32 shards. Let's just find the one that has it.
    for sf in result["shards"]:
        s_data = json.loads(sf.read_text(encoding="utf-8"))
        if "@test/destructive-server" in s_data:
            server_data = s_data["@test/destructive-server"]
            break
    
    tools = server_data["versions"][0]["tools"]
    assert len(tools) == 2
    tool_annotations_1 = next(t["annotations"] for t in tools if t["name"] == "delete_files")
    assert tool_annotations_1["destructiveHint"] is True
    
    tool_annotations_2 = next(t["annotations"] for t in tools if t["name"] == "read_files")
    assert tool_annotations_2["readOnlyHint"] is True

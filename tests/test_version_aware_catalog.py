import json
import pytest
from pathlib import Path

from mcp_vulnerabilities.catalog import (
    ToolSecurityAssessment,
    VersionSecurityRecord,
    UnifiedMcpSecurityRecord,
    build_unified_mcp_security_catalog,
)
from mcp_vulnerabilities.fingerprints.models import (
    ParameterMetadata,
    PromptSignature,
    ResourceSignature,
    ServerPackageSpec,
    ToolContractSignature,
    VersionFingerprint,
)
from mcp_vulnerabilities.models import OsvVulnerability


def test_models_roundtrip():
    param = ParameterMetadata(
        name="param1",
        type="string",
        description="A test parameter",
        required=True,
        default="default_val",
        enum=("opt1", "opt2"),
    )
    p_dict = param.to_dict()
    assert p_dict["name"] == "param1"
    assert p_dict["required"] is True
    assert p_dict["enum"] == ["opt1", "opt2"]

    restored_param = ParameterMetadata.from_dict(p_dict)
    assert restored_param.name == "param1"
    assert restored_param.required is True
    assert restored_param.enum == ("opt1", "opt2")

    res = ResourceSignature(
        uri_template="file:///{path}",
        name="test_res",
        description="Resource test",
        mime_type="text/plain",
    )
    r_dict = res.to_dict()
    assert r_dict["uri_template"] == "file:///{path}"
    restored_res = ResourceSignature.from_dict(r_dict)
    assert restored_res.name == "test_res"

    tool = ToolContractSignature(
        name="execute_cmd",
        canonical_hash="hash123",
        description="Run bash command",
        parameters=(param,),
        annotations={"readOnlyHint": False, "destructiveHint": True},
    )
    t_dict = tool.to_dict()
    assert len(t_dict["parameters"]) == 1
    assert t_dict["annotations"]["destructiveHint"] is True
    restored_tool = ToolContractSignature.from_dict(t_dict)
    assert len(restored_tool.parameters) == 1
    assert restored_tool.parameters[0].name == "param1"


def test_version_security_record_and_unified_catalog_model():
    tool_assessment = ToolSecurityAssessment(
        name="execute_command",
        canonical_hash="hash123",
        description="Executes a command",
        risk_score=9.5,
        risk_tier="CRITICAL",
        security_comment="Tool executes arbitrary commands.",
    )
    t_dict = tool_assessment.to_dict()
    assert t_dict["risk_tier"] == "CRITICAL"
    restored_t = ToolSecurityAssessment.from_dict(t_dict)
    assert restored_t.risk_score == 9.5

    v_vuln = VersionSecurityRecord(
        version="1.0.0",
        is_vulnerable=True,
        advisories=[],
        tools=[tool_assessment],
    )
    v_safe = VersionSecurityRecord(
        version="1.0.1",
        is_vulnerable=False,
        advisories=[],
        tools=[tool_assessment],
    )
    assert v_vuln.is_vulnerable is True
    assert v_safe.is_vulnerable is False

    unified = UnifiedMcpSecurityRecord(
        package_name="test-server",
        ecosystem="npm",
        purl="pkg:npm/test-server",
        display_name="Test Server",
        latest_version="1.0.1",
        recommended_safe_version="1.0.1",
        is_vulnerable=True,
        security_summary="Server has vulnerable earlier versions.",
        versions=[v_vuln, v_safe],
    )
    u_dict = unified.to_dict()
    assert u_dict["package_name"] == "test-server"
    assert u_dict["recommended_safe_version"] == "1.0.1"
    assert len(u_dict["versions"]) == 2

    restored_u = UnifiedMcpSecurityRecord.from_dict(u_dict)
    assert restored_u.package_name == "test-server"
    assert restored_u.recommended_safe_version == "1.0.1"
    assert restored_u.versions[0].is_vulnerable is True
    assert restored_u.versions[1].is_vulnerable is False


def test_build_unified_mcp_security_catalog_version_separation(tmp_path: Path):
    # Setup mock passport directory
    passports_dir = tmp_path / "passports"
    passports_dir.mkdir()

    tool1 = ToolContractSignature(
        name="read_file",
        canonical_hash="hash_rf",
        description="Read file from disk",
        property_keys=("path",),
        required_keys=("path",),
    )

    vf_1_0_0 = VersionFingerprint(
        version="1.0.0",
        toolset_canonical_hash="t_hash_1",
        tool_signatures=(tool1,),
    )
    vf_1_1_0 = VersionFingerprint(
        version="1.1.0",
        toolset_canonical_hash="t_hash_2",
        tool_signatures=(tool1,),
    )

    pkg = ServerPackageSpec(
        package_name="@test/mcp-server",
        purl="pkg:npm/%40test/mcp-server",
        ecosystem="npm",
        display_name="Test MCP Server",
        versions=(vf_1_0_0, vf_1_1_0),
    )

    pkg_file = passports_dir / "test_pkg.json"
    pkg_file.write_text(json.dumps(pkg.to_dict()))

    # Setup mock vulnerabilities directory
    vuln_dir = tmp_path / "vulnerabilities"
    vuln_dir.mkdir()

    advisory_data = {
        "id": "GHSA-test-1234",
        "schema_version": "1.6.0",
        "summary": "Path traversal in @test/mcp-server",
        "details": "Vulnerability details",
        "affected": [
            {
                "package": {
                    "name": "@test/mcp-server",
                    "ecosystem": "npm",
                },
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.1.0"},
                        ],
                    }
                ],
            }
        ],
    }
    adv_file = vuln_dir / "GHSA-test-1234.json"
    adv_file.write_text(json.dumps(advisory_data))

    # Build catalog
    catalog = build_unified_mcp_security_catalog(
        passports_path=passports_dir,
        vulnerabilities_dir=vuln_dir,
    )

    assert "@test/mcp-server" in catalog
    record = catalog["@test/mcp-server"]

    assert record.package_name == "@test/mcp-server"
    assert len(record.versions) == 2

    v1_0_0 = next(v for v in record.versions if v.version == "1.0.0")
    v1_1_0 = next(v for v in record.versions if v.version == "1.1.0")

    # Verify per-version separation:
    # 1.0.0 is affected by GHSA-test-1234
    assert v1_0_0.is_vulnerable is True
    assert len(v1_0_0.advisories) == 1
    assert v1_0_0.advisories[0].id == "GHSA-test-1234"

    # 1.1.0 is safe (fixed)
    assert v1_1_0.is_vulnerable is False
    assert len(v1_1_0.advisories) == 0

    # Recommended safe version must be 1.1.0
    assert record.recommended_safe_version == "1.1.0"
    assert record.latest_version == "1.1.0"
    assert record.is_vulnerable is True
    assert len(v1_0_0.tools) == 1
    assert v1_0_0.tools[0].name == "read_file"

import json
import pytest
import sys
from pathlib import Path

# Add tests directory to sys.path
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mcp_vulnerabilities.site_builder import build_static_site_data


def test_web_dual_axis_integration(tmp_path):
    # Create mock passport with dual_axis_assessment
    mock_passport = {
        "passports": {
            "test-server": {
                "passport_schema_version": "1.1.0",
                "package_name": "test-server",
                "ecosystem": "npm",
                "purl": "pkg:npm/test-server",
                "versions": [
                    {
                        "version": "1.0.0",
                        "release_date": "2023-01-01",
                        "tool_signatures": [],
                        "prompt_signatures": [],
                        "resource_signatures": [],
                        "required_env_vars": [],
                        "toolset_canonical_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    }
                ],
                "dual_axis_assessment": {
                    "status": "SCANNED",
                    "has_vulnerabilities": True,
                    "protocol_trust": {
                        "tool_risk_tier": "HIGH",
                        "risk_score": 7.5,
                        "capability_profile": "Read/Write",
                        "authenticity_verified": True
                    },
                    "supply_chain_hygiene": {
                        "hygiene_status": "VULNERABLE",
                        "vulnerabilities": ["CVE-2023-1234"],
                        "cvss_max": 8.1
                    }
                }
            }
        }
    }

    passports_file = tmp_path / "passports.json"
    passports_file.write_text(json.dumps(mock_passport))

    docs_data_dir = tmp_path / "docs_data"
    docs_data_dir.mkdir(parents=True)
    
    vulns_dir = tmp_path / "vulns"
    vulns_dir.mkdir()
    
    # Run site builder
    build_static_site_data(
        data_dir=str(vulns_dir),
        output_dir=str(docs_data_dir),
        passports_path=str(passports_file),
        num_shards=1
    )
    
    # Verify index output
    index_file = docs_data_dir / "mcp_catalog_index.json"
    assert index_file.exists()
    
    index_data = json.loads(index_file.read_text())
    assert len(index_data) == 1
    
    record = index_data[0]
    assert record["dual_axis_status"] == "SCANNED"
    assert record["protocol_trust_tier"] == "HIGH"
    assert record["protocol_trust_score"] == 7.5
    assert record["supply_chain_cve_count"] == 1
    assert record["supply_chain_max_cvss"] == 8.1
    
    # Verify shard output
    shard_file = docs_data_dir / "shards" / "shard_00.json"
    assert shard_file.exists()
    
    shard_data = json.loads(shard_file.read_text())
    assert "test-server" in shard_data
    
    shard_record = shard_data["test-server"]
    assert "dual_axis_assessment" in shard_record
    assert shard_record["dual_axis_assessment"]["status"] == "SCANNED"
    assert shard_record["dual_axis_assessment"]["protocol_trust"]["tool_risk_tier"] == "HIGH"



"""Tests for the unified version-aware static site builder and sharded datasets."""

import json
from pathlib import Path

import pytest

from mcp_vulnerabilities.site_builder import build_static_site_data


def test_build_static_site_data_minimal(tmp_path: Path):
    vuln_dir = tmp_path / "vulnerabilities"
    vuln_dir.mkdir()

    test_adv = {
        "id": "GHSA-test-site-001",
        "summary": "Test advisory for unified site builder",
        "details": "Extended details about this vulnerability",
        "modified": "2026-10-16T00:00:00Z",
        "affected": [
            {
                "package": {"name": "test-pkg", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}],
                "versions": ["1.0.0"],
                "database_specific": {
                    "vulnerable_tools": ["exec_cmd"],
                    "owasp_mcp_category": "MCP01 - Tool Poisoning",
                    "cvss_score": 8.5,
                    "severity": "HIGH",
                },
            }
        ],
    }
    (vuln_dir / "GHSA-test-site-001.json").write_text(
        json.dumps(test_adv), encoding="utf-8"
    )

    out_dir = tmp_path / "docs_data"
    result = build_static_site_data(
        data_dir=vuln_dir,
        output_dir=out_dir,
        passports_path=None,
        num_shards=4,
    )

    assert result["vulnerabilities"].exists()
    assert result["mcp_catalog_index"].exists()
    assert result["analytics"].exists()
    assert len(result["shards"]) == 4

    # Verify vulnerabilities.json
    advs = json.loads(result["vulnerabilities"].read_text(encoding="utf-8"))
    assert len(advs) == 1
    assert advs[0]["id"] == "GHSA-test-site-001"

    # Verify mcp_catalog_index.json
    index = json.loads(result["mcp_catalog_index"].read_text(encoding="utf-8"))
    assert len(index) >= 1
    entry = next(e for e in index if e["package_name"] == "test-pkg")
    assert entry["is_vulnerable"] is True
    assert entry["vulnerable_versions_count"] >= 1
    assert entry["highest_cve_severity"] == "HIGH"
    assert entry["composite_risk_tier"] == "HIGH"
    assert "shard_file" in entry
    assert "shard_id" in entry

    # Verify analytics.json
    analytics = json.loads(result["analytics"].read_text(encoding="utf-8"))
    assert analytics["total_advisories"] == 1
    assert analytics["total_servers"] >= 1
    assert analytics["vulnerable_servers_count"] >= 1
    assert any(item["tool"] == "exec_cmd" for item in analytics["top_tools"])

    # Verify shards contain version-separated data
    shard_file = out_dir / "shards" / entry["shard_file"]
    assert shard_file.exists()
    shard_data = json.loads(shard_file.read_text(encoding="utf-8"))
    assert entry["package_name"] in shard_data
    server_record = shard_data[entry["package_name"]]
    assert "versions" in server_record
    assert len(server_record["versions"]) >= 1
    ver = server_record["versions"][0]
    assert "advisories" in ver
    assert "toolset_canonical_hash" in ver
    assert "tools" in ver


def test_build_static_site_data_live_catalog():
    """Verify live catalog data generation conforms to VC-39V.1 and VC-39V.2."""
    index_file = Path("docs/data/mcp_catalog_index.json")
    vuln_file = Path("docs/data/vulnerabilities.json")
    analytics_file = Path("docs/data/analytics.json")
    shards_dir = Path("docs/data/shards")

    assert index_file.exists(), "mcp_catalog_index.json not found"
    assert vuln_file.exists(), "vulnerabilities.json not found"
    assert analytics_file.exists(), "analytics.json not found"
    assert shards_dir.exists(), "shards directory not found"

    index_data = json.loads(index_file.read_text(encoding="utf-8"))
    assert len(index_data) >= 5050, f"Expected >= 5050 MCP server records, got {len(index_data)}"

    # Check shard count and version structure
    shards = list(shards_dir.glob("shard_*.json"))
    assert len(shards) == 32

    # Verify a sampled server from index in shard
    sample_entry = index_data[0]
    shard_path = shards_dir / sample_entry["shard_file"]
    assert shard_path.exists()

    shard_data = json.loads(shard_path.read_text(encoding="utf-8"))
    assert sample_entry["package_name"] in shard_data
    record = shard_data[sample_entry["package_name"]]
    assert "versions" in record
    for v in record["versions"]:
        assert "advisories" in v
        assert "toolset_canonical_hash" in v
        assert "tools" in v


def test_latest_version_analytics_and_catalog_ingestion(tmp_path: Path):
    """Verify catalog_index and analytics.json ingest tools and env_vars from the latest version."""
    vuln_dir = tmp_path / "vulnerabilities"
    vuln_dir.mkdir()

    mock_passports_path = tmp_path / "passports.json"
    passports_data = {
        "passports": {
            "test-latest-pkg": {
                "package_name": "test-latest-pkg",
                "purl": "pkg:pypi/test-latest-pkg",
                "ecosystem": "PyPI",
                "versions": [
                    {
                        "version": "0.1.0",
                        "toolset_canonical_hash": "set_hash_v010",
                        "tool_signatures": [
                            {"name": "read_file", "canonical_hash": "hash1"}
                        ],
                        "required_env_vars": [],
                    },
                    {
                        "version": "1.0.0",
                        "toolset_canonical_hash": "set_hash_v100",
                        "tool_signatures": [
                            {"name": "read_file", "canonical_hash": "hash1"},
                            {"name": "write_file", "canonical_hash": "hash2"},
                            {"name": "exec_cmd", "canonical_hash": "hash3"},
                        ],
                        "required_env_vars": ["API_KEY", "FOO"],
                    },
                ],
            }
        }
    }
    mock_passports_path.write_text(json.dumps(passports_data), encoding="utf-8")

    out_dir = tmp_path / "docs_data"
    result = build_static_site_data(
        data_dir=vuln_dir,
        output_dir=out_dir,
        passports_path=mock_passports_path,
        use_cache=False,
        num_shards=4,
    )

    index_data = json.loads(result["mcp_catalog_index"].read_text(encoding="utf-8"))
    entry = next(e for e in index_data if e["package_name"] == "test-latest-pkg")
    assert entry["tools_count"] == 3
    assert len(entry["tools_sample"]) == 3
    assert "API_KEY" in entry["required_env_vars"]

    analytics_data = json.loads(result["analytics"].read_text(encoding="utf-8"))
    top_secrets = {s["name"]: s["count"] for s in analytics_data.get("top_secrets", [])}
    assert top_secrets.get("API_KEY") == 1
    assert top_secrets.get("FOO") == 1
    assert analytics_data.get("capabilities", {}).get("shell_exec") == 1


def test_composite_risk_tier_and_highest_cve_severity_stamping(tmp_path: Path):
    """Verify INVARIANT_79_1A, 1B, 1C: composite_risk_tier & highest_cve_severity stamping."""
    vuln_dir = tmp_path / "vulnerabilities"
    vuln_dir.mkdir()

    crit_adv = {
        "id": "GHSA-test-crit-001",
        "summary": "Critical RCE vulnerability",
        "details": "Remote code execution via tool arguments",
        "modified": "2026-10-16T00:00:00Z",
        "affected": [
            {
                "package": {"name": "low-static-crit-cve-pkg", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
                "versions": ["1.0.0"],
                "database_specific": {
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                },
            }
        ],
    }
    (vuln_dir / "GHSA-test-crit-001.json").write_text(json.dumps(crit_adv), encoding="utf-8")

    mock_passports_path = tmp_path / "passports.json"
    passports_data = {
        "passports": {
            "low-static-crit-cve-pkg": {
                "package_name": "low-static-crit-cve-pkg",
                "purl": "pkg:pypi/low-static-crit-cve-pkg",
                "ecosystem": "PyPI",
                "versions": [
                    {
                        "version": "1.0.0",
                        "toolset_canonical_hash": "hash_v100",
                        "tool_signatures": [],
                    }
                ],
            },
            "clean-pkg": {
                "package_name": "clean-pkg",
                "purl": "pkg:pypi/clean-pkg",
                "ecosystem": "PyPI",
                "versions": [
                    {
                        "version": "1.0.0",
                        "toolset_canonical_hash": "hash_v100",
                        "tool_signatures": [],
                    }
                ],
            },
        }
    }
    mock_passports_path.write_text(json.dumps(passports_data), encoding="utf-8")

    out_dir = tmp_path / "docs_data"
    result = build_static_site_data(
        data_dir=vuln_dir,
        output_dir=out_dir,
        passports_path=mock_passports_path,
        use_cache=False,
        num_shards=4,
    )

    index_data = json.loads(result["mcp_catalog_index"].read_text(encoding="utf-8"))
    vuln_entry = next(e for e in index_data if e["package_name"] == "low-static-crit-cve-pkg")
    assert vuln_entry["static_risk_tier"] == "LOW"
    assert vuln_entry["highest_cve_severity"] == "CRITICAL"
    assert vuln_entry["composite_risk_tier"] == "CRITICAL"

    clean_entry = next(e for e in index_data if e["package_name"] == "clean-pkg")
    assert clean_entry["is_vulnerable"] is False
    assert clean_entry["highest_cve_severity"] is None
    assert clean_entry["composite_risk_tier"] == "LOW"



import json
from pathlib import Path
import pytest

from mcp_vulnerabilities.site_builder import build_static_site_data


def test_build_static_site_data_analytics(tmp_path: Path):
    vuln_dir = tmp_path / "vulnerabilities"
    vuln_dir.mkdir()

    # Remediable advisory
    adv1 = {
        "id": "GHSA-rem-0001",
        "summary": "Remediable vuln",
        "modified": "2026-10-16T00:00:00Z",
        "affected": [
            {
                "package": {"name": "remediable-pkg", "ecosystem": "PyPI"},
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

    # Zero-day advisory (no fixed version)
    adv2 = {
        "id": "GHSA-zero-0001",
        "summary": "Zero-day vuln",
        "modified": "2026-10-16T00:00:00Z",
        "affected": [
            {
                "package": {"name": "zeroday-pkg", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                "versions": ["1.0.0"],
            }
        ],
    }

    (vuln_dir / "GHSA-rem-0001.json").write_text(json.dumps(adv1), encoding="utf-8")
    (vuln_dir / "GHSA-zero-0001.json").write_text(json.dumps(adv2), encoding="utf-8")

    passports = {
        "passports": {
            "remediable-pkg": {
                "package_name": "remediable-pkg",
                "ecosystem": "PyPI", "purl": "pkg:pypi/remediable-pkg",
                "transport": "stdio",
                "versions": [
                    {
                        "version": "1.0.0",
                        "tool_signatures": [
                            {"name": "exec_shell", "canonical_hash": "hash1", "description": "Run shell"}
                        ],
                        "prompt_signatures": [], "toolset_canonical_hash": "dummy", "release_date": "2024-01-01T00:00:00Z",
                        "resource_signatures": [],
                        "required_env_vars": ["SECRET_KEY"]
                    },
                    {
                        "version": "1.2.0",
                        "tool_signatures": [
                            {"name": "exec_shell", "canonical_hash": "hash2", "description": "Run shell"}
                        ],
                        "prompt_signatures": [], "toolset_canonical_hash": "dummy", "release_date": "2024-01-01T00:00:00Z",
                        "resource_signatures": [],
                        "required_env_vars": ["SECRET_KEY"]
                    }
                ]
            },
            "zeroday-pkg": {
                "package_name": "zeroday-pkg",
                "ecosystem": "npm", "purl": "pkg:npm/zeroday-pkg",
                "transport": "sse",
                "versions": [
                    {
                        "version": "1.0.0",
                        "tool_signatures": [
                            {"name": "read_file", "canonical_hash": "hash3", "description": "Read a file"},
                            {"name": "http_fetch", "canonical_hash": "hash4", "description": "Fetch from network"},
                            {"name": "create_record", "canonical_hash": "hash5", "description": "Create db record"}
                        ],
                        "prompt_signatures": [], "toolset_canonical_hash": "dummy", "release_date": "2024-01-01T00:00:00Z",
                        "resource_signatures": [],
                        "required_env_vars": ["API_TOKEN"]
                    }
                ]
            },
            "safe-pkg": {
                "package_name": "safe-pkg",
                "ecosystem": "go", "purl": "pkg:golang/safe-pkg",
                "transport": "stdio",
                "versions": [
                    {
                        "version": "2.0.0",
                        "tool_signatures": [
                            {"name": "get_status", "canonical_hash": "hash6", "description": "Read only status"}
                        ],
                        "prompt_signatures": [], "toolset_canonical_hash": "dummy", "release_date": "2024-01-01T00:00:00Z",
                        "resource_signatures": [],
                        "required_env_vars": []
                    }
                ]
            },
            "shadow-pkg": {
                "package_name": "shadow-pkg",
                "ecosystem": "npm", "purl": "pkg:npm/zeroday-pkg",
                "transport": "stdio",
                "versions": [
                    {
                        "version": "1.0.0",
                        "tool_signatures": [
                            {"name": "read_file", "canonical_hash": "hash_shadow", "description": "Different read file"}
                        ],
                        "prompt_signatures": [], "toolset_canonical_hash": "dummy", "release_date": "2024-01-01T00:00:00Z",
                        "resource_signatures": [],
                        "required_env_vars": []
                    }
                ]
            }
        }
    }

    passports_file = tmp_path / "passports.json"
    passports_file.write_text(json.dumps(passports), encoding="utf-8")

    out_dir = tmp_path / "docs_data"
    result = build_static_site_data(
        data_dir=vuln_dir,
        output_dir=out_dir,
        passports_path=passports_file,
        num_shards=4,
        workers=1,
        use_cache=False,
    )

    analytics_file = result["analytics"]
    analytics = json.loads(analytics_file.read_text(encoding="utf-8"))

    # Assert basic math
    assert analytics["patched_remediable_count"] == 1
    assert analytics["zero_day_unpatched_count"] == 1
    assert analytics["vulnerable_servers_count"] == 2
    assert analytics["safe_servers_count"] == 2
    assert analytics["total_servers"] == 4

    # Assert capabilities surface
    caps = analytics["capabilities"]
    assert caps["fs_read_write"] >= 1
    assert caps["shell_exec"] >= 1
    assert caps["network_egress"] >= 1
    assert caps["mutating"] >= 1
    assert caps["read_only"] >= 1
    
    # Assert secrets perimeter
    secrets = {s["name"]: s["count"] for s in analytics["top_secrets"]}
    assert "SECRET_KEY" in secrets
    assert "API_TOKEN" in secrets

    # Assert transports
    transports = analytics["transports"]
    assert transports.get("stdio", 0) >= 2
    assert transports.get("sse", 0) >= 1

    # Assert tool shadowing
    shadows = {s["tool"]: s["entropy"] for s in analytics["tool_shadowing"]}
    assert shadows.get("read_file", 0) >= 2

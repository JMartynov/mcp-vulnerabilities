import os
import sys
import json
import tempfile
import pytest
from pathlib import Path

# Add scripts directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scripts.audit_web_cards import is_valid_url
from mcp_vulnerabilities.site_builder import _compute_composite_risk, _extract_advisory_severity

def get_highest_cve_severity(advisories):
    rank_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "MODERATE": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}
    tier_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "LOW"}
    max_rank = 0
    for adv in advisories:
        sev = _extract_advisory_severity(adv)
        rank = rank_map.get(sev.upper(), 0)
        if rank > max_rank:
            max_rank = rank
    if max_rank == 0 and len(advisories) > 0:
        return "HIGH"
    return tier_map[max_rank]

def test_is_valid_url():
    assert is_valid_url("https://example.com") == True
    assert is_valid_url("http://github.com/foo/bar") == True
    assert is_valid_url(None) == True
    assert is_valid_url("") == True
    assert is_valid_url("not a url") == False
    assert is_valid_url("mcp.noteboxd.com") == True

def test_compute_composite_risk():
    assert _compute_composite_risk("LOW", False, [])[1] == "LOW"
    assert _compute_composite_risk("LOW", True, [{"is_vulnerable": True, "advisories": [{"severity": "HIGH"}]}])[1] == "HIGH"
    assert _compute_composite_risk("CRITICAL", True, [{"is_vulnerable": True, "advisories": [{"severity": "LOW"}]}])[1] == "CRITICAL"
    assert _compute_composite_risk(None, True, [{"is_vulnerable": True, "advisories": []}])[1] == "HIGH"
    assert _compute_composite_risk("MODERATE", True, [{"is_vulnerable": True, "advisories": [{"severity": "CRITICAL"}]}])[1] == "CRITICAL"

def test_get_highest_cve_severity():
    advs = [
        {"database_specific": {"severity": "LOW"}},
        {"database_specific": {"severity": "CRITICAL"}},
        {"database_specific": {"severity": "HIGH"}}
    ]
    assert get_highest_cve_severity(advs) == "CRITICAL"
    
    assert get_highest_cve_severity([]) == "LOW"
    
    assert get_highest_cve_severity([{}]) == "CRITICAL"

def test_audit_script_execution(monkeypatch, tmp_path):
    catalog_path = tmp_path / "catalog.json"
    shards_dir = tmp_path / "shards"
    shards_dir.mkdir()
    vuln_dir = tmp_path / "vulns"
    vuln_dir.mkdir()
    report_dir = tmp_path / "reports"
    
    catalog_data = [
        {
            "id": "MCP:ValidPkg",
            "package_name": "ValidPkg",
            "shard_file": "shard_01.json",
            "is_vulnerable": True,
            "highest_cve_severity": "HIGH",
            "static_risk_tier": "LOW",
            "composite_risk_tier": "HIGH",
            "repository_url": "https://github.com/valid/pkg"
        },
        {
            "id": "MCP:InvalidPkg",
            "package_name": "InvalidPkg",
            "shard_file": "shard_02.json",
            "tools_count": -1,
            "repository_url": "not-a-url"
        }
    ]
    catalog_path.write_text(json.dumps(catalog_data))
    
    shard_01 = shards_dir / "shard_01.json"
    shard_01.write_text(json.dumps({"ValidPkg": {}}))
    
    # Missing shard_02 on purpose
    
    adv_data = {
        "id": "CVE-1234-5678",
        "affected": [
            {"package": {"name": "ValidPkg"}}
        ],
        "database_specific": {"severity": "HIGH"}
    }
    (vuln_dir / "adv1.json").write_text(json.dumps(adv_data))
    
    monkeypatch.setattr("sys.argv", [
        "audit_web_cards.py",
        "--catalog", str(catalog_path),
        "--shards-dir", str(shards_dir),
        "--vulnerabilities", str(vuln_dir),
        "--report-dir", str(report_dir),
        "--strict"
    ])
    
    from scripts.audit_web_cards import audit
    
    with pytest.raises(SystemExit) as e:
        audit()
        
    assert e.type == SystemExit
    assert e.value.code == 1
    
    assert (report_dir / "audit_latest.json").exists()
    
    with open(report_dir / "audit_latest.json") as f:
        report = json.load(f)
        
    assert report["total_packages"] == 2
    assert report["discrepancies_count"] > 0
    
    discrepancies_text = " ".join(report["discrepancies"])
    assert "negative tools_count" in discrepancies_text
    assert "invalid repository_url" in discrepancies_text
    assert "missing for InvalidPkg: shard_02.json" in discrepancies_text

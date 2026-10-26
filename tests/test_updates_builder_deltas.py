import json
from pathlib import Path
import sys
from unittest import mock

from mcp_vulnerabilities.updates_builder import build_updates_data
from unittest.mock import patch, MagicMock

def test_updates_builder_deltas(tmp_path: Path):
    out_dir = tmp_path / "updates"
    out_dir.mkdir()
    
    # Create an initial history simulating a previous release
    prev_history = [
        {
            "release_version": "1.0.0",
            "timestamp_utc": "2026-10-17T01:28:05Z",
            "cumulative_totals": {
                "total_advisories": 100,
                "total_servers": 50,
                "total_versions": 80
            },
            "data_file": "v1.0.0.json"
        }
    ]
    (out_dir / "updates_history.json").write_text(json.dumps(prev_history), encoding="utf-8")
    
    vuln_dir = tmp_path / "vulnerabilities"
    vuln_dir.mkdir()
    
    # 2 new advisories
    adv1 = {"id": "CVE-NEW-1", "affected": [{"package": {"name": "s1"}}]}
    adv2 = {"id": "CVE-NEW-2", "affected": [{"package": {"name": "s2"}}]}
    (vuln_dir / "a1.json").write_text(json.dumps(adv1), encoding="utf-8")
    (vuln_dir / "a2.json").write_text(json.dumps(adv2), encoding="utf-8")
    
    class MockRecord:
        def __init__(self, name, is_vuln=True, vers=None):
            self.package_name = name
            self.is_vulnerable = is_vuln
            self.versions = vers or [MagicMock(is_vulnerable=True)]
        
        def to_dict(self):
            return {
                "package_name": self.package_name,
                "is_vulnerable": self.is_vulnerable,
                "versions": [{"version": "1.0", "is_vulnerable": True, "advisories": [{"id": "CVE-NEW-1"}]}]
            }
            
    mock_catalog = {
        "s1": MockRecord("s1", vers=[MagicMock(is_vulnerable=True), MagicMock(is_vulnerable=False)]),
        "s2": MockRecord("s2"),
        "s3": MockRecord("s3")
    }
    
    with patch("mcp_vulnerabilities.updates_builder.build_unified_mcp_security_catalog", return_value=mock_catalog):
        build_updates_data(output_dir=out_dir, version="1.0.1", vulnerabilities_dir=vuln_dir)
        
    history = json.loads((out_dir / "updates_history.json").read_text(encoding="utf-8"))
    assert len(history) == 2
    
    latest_entry = history[0]
    assert latest_entry["release_version"] == "1.0.1"
    
    assert latest_entry["summary_counts"]["new_advisories"] == 0
    assert latest_entry["summary_counts"]["new_mcp_servers"] == 0
    assert latest_entry["summary_counts"]["updated_mcp_versions"] == 0
    
    prev_history2 = [
        {
            "release_version": "1.0.0",
            "cumulative_totals": {
                "total_advisories": 1,
                "total_servers": 1,
                "total_versions": 1
            },
            "data_file": "v1.0.0.json"
        }
    ]
    (out_dir / "updates_history.json").write_text(json.dumps(prev_history2), encoding="utf-8")
    
    with patch("mcp_vulnerabilities.updates_builder.build_unified_mcp_security_catalog", return_value=mock_catalog):
        build_updates_data(output_dir=out_dir, version="1.0.1", vulnerabilities_dir=vuln_dir)
        
    history = json.loads((out_dir / "updates_history.json").read_text(encoding="utf-8"))
    latest_entry = history[0]
    
    assert latest_entry["summary_counts"]["new_advisories"] == 1
    assert latest_entry["summary_counts"]["new_mcp_servers"] == 2
    assert latest_entry["summary_counts"]["updated_mcp_versions"] == 3

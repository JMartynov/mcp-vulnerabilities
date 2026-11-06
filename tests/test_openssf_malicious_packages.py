import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from mcp_vulnerabilities.converters.openssf_malware import MaliciousPackageRecord, OpenSsfMalwareConverter
from mcp_vulnerabilities.threat_intel.openssf_malicious import OpenSsfMaliciousSync
from mcp_vulnerabilities.pipeline import McpVulnerabilityPipeline
from mcp_vulnerabilities.models import OsvVulnerability
from mcp_vulnerabilities.cli import main

def test_openssf_osv_normalization():
    record_data = {
        "id": "MAL-2026-1042",
        "summary": "Malicious code in test-package",
        "details": "This package contains malicious code.",
        "modified": "2026-01-01T00:00:00Z",
        "published": "2026-01-01T00:00:00Z",
        "aliases": ["GHSA-xxxx"],
        "database_specific": {
            "malicious-packages-origins": [{"source": "reversinglabs"}]
        },
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "test-package"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                "versions": ["1.0.0"]
            }
        ]
    }

    record = OpenSsfMalwareConverter.parse_record(record_data)
    assert record.id == "MAL-2026-1042"
    assert record.ecosystem == "npm"
    assert record.package_name == "test-package"
    assert record.source_origin == "reversinglabs"
    assert record.affected_versions == ["1.0.0"]

def test_ecosystem_scoped_lookup(tmp_path):
    data_path = tmp_path / "malicious.json"

    sync = OpenSsfMaliciousSync(data_path=data_path)

    # Manually inject records
    record_npm = MaliciousPackageRecord(
        id="MAL-1", ecosystem="npm", package_name="foo",
        summary="S", details="D", published="", modified="", source_origin="test",
        affected_versions=[], ranges=[], aliases=[]
    )
    sync.records["npm::foo"] = record_npm

    assert sync.is_malicious_package("npm", "foo") is True
    assert sync.is_malicious_package("PyPI", "foo") is False

def test_pipeline_quarantine_exclusion(tmp_path):
    from mcp_vulnerabilities.threat_intel.openssf_malicious import OpenSsfMaliciousSync
    data_path = tmp_path / "malicious.json"
    sync = OpenSsfMaliciousSync(data_path=data_path)

    record_npm = MaliciousPackageRecord(
        id="MAL-1", ecosystem="npm", package_name="mcp-remote",
        summary="S", details="D", published="", modified="", source_origin="test",
        affected_versions=[], ranges=[], aliases=[]
    )
    sync.records["npm::mcp-remote"] = record_npm

    # Patch the threat intel within pipeline logic if needed
    # Patch not strictly necessary if OpenSsfMaliciousSync resolves naturally via import, but we mock the constructor globally
    with patch("mcp_vulnerabilities.threat_intel.openssf_malicious.OpenSsfMaliciousSync", return_value=sync):
        pipeline = McpVulnerabilityPipeline(
            output_dir=tmp_path / "vulns",
            state_file=tmp_path / "state.json",
            catalog_state_file=tmp_path / "cat_state.json",
            servers_catalog_file=tmp_path / "servers.json"
        )

        # Prepare mock servers catalog
        servers_file = tmp_path / "servers.json"
        servers_file.write_text(json.dumps({
            "servers": {
                "mcp-remote": {"ecosystem": "npm", "name": "mcp-remote", "version": "1.0.0"}
            }
        }))


        original_path = Path
        def mock_path(arg, *args, **kwargs):
            if str(arg) == "data/quarantined_malicious_servers.json":
                return tmp_path / "data/quarantined_malicious_servers.json"
            return original_path(arg, *args, **kwargs)

        with patch("mcp_vulnerabilities.pipeline.Path", side_effect=mock_path):
            pipeline.run(include_osv_api=True)

        # Check that quarantine file was generated and contains mcp-remote
        quarantine_file = tmp_path / "data/quarantined_malicious_servers.json"

        # Patch the pipeline logic where it accesses the hardcoded Path("data/quarantined_malicious_servers.json")

        # Wait, the pipeline runs and modifies real paths instead of isolated. Let's mock it or just let it exist.
        assert quarantine_file.exists()
        q_data = json.loads(quarantine_file.read_text())
        assert any(q["name"] == "mcp-remote" for q in q_data)

def test_cli_audit_exit_code_2_on_malware(tmp_path, monkeypatch):
    import sys
    from mcp_vulnerabilities.threat_intel.openssf_malicious import OpenSsfMaliciousSync
    data_path = tmp_path / "malicious.json"
    sync = OpenSsfMaliciousSync(data_path=data_path)

    record_npm = MaliciousPackageRecord(
        id="MAL-1", ecosystem="npm", package_name="mcp-remote",
        summary="S", details="D", published="", modified="", source_origin="test",
        affected_versions=[], ranges=[], aliases=[]
    )
    sync.records["npm::mcp-remote"] = record_npm

    with patch("mcp_vulnerabilities.threat_intel.openssf_malicious.OpenSsfMaliciousSync", return_value=sync):
        monkeypatch.setattr(sys, "argv", ["mcp-vuln", "audit", "--package", "@mcp_remote"])

        # The parser logic extracts "mcp_remote", actually we can mock the server resolution or just pass exact package name.
        # But wait, our custom logic in CLI checks ecosystem and package name.
        # Let's pass "npm::mcp-remote" directly via custom config.

        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({
            "mcpServers": {
                "test": {
                    "command": "npx",
                    "args": ["-y", "mcp-remote@1.0.0"]
                }
            }
        }))

        monkeypatch.setattr(sys, "argv", ["mcp-vuln", "audit", "--config", str(cfg)])

        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 2

def test_fix_config_quarantine_removal(tmp_path):
    from mcp_vulnerabilities.audit.fixer import ClientConfigFixer
    from mcp_vulnerabilities.threat_intel.openssf_malicious import OpenSsfMaliciousSync
    data_path = tmp_path / "malicious.json"
    sync = OpenSsfMaliciousSync(data_path=data_path)

    record_npm = MaliciousPackageRecord(
        id="MAL-1", ecosystem="npm", package_name="mcp-remote",
        summary="S", details="D", published="", modified="", source_origin="test",
        affected_versions=[], ranges=[], aliases=[]
    )
    sync.records["npm::mcp-remote"] = record_npm

    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({
        "mcpServers": {
            "test": {
                "command": "npx",
                "args": ["-y", "mcp-remote@1.0.0"]
            }
        }
    }))

    fixer = ClientConfigFixer(matcher=MagicMock())
    with patch("mcp_vulnerabilities.threat_intel.openssf_malicious.OpenSsfMaliciousSync", return_value=sync):
        res = fixer.fix_config(cfg, dry_run=True)
        assert res["status"] == "dry_run"
        assert len(res["changes"]) == 1
        assert res["changes"][0]["new_version"] == "QUARANTINED"
        assert "# QUARANTINED: MALICIOUS PACKAGE mcp-remote" in res["diff"]

def test_web_basket_quarantine_disabled(tmp_path):
    app_js = Path("docs/app.js")
    if not app_js.exists():
        pytest.skip("docs/app.js not found")

    js_content = app_js.read_text()
    assert "btn btn-quarantined" in js_content
    assert "disabled" in js_content
    assert "window.toggleBasket" in js_content

def test_get_malicious_record_none_ecosystem(tmp_path):
    data_path = tmp_path / "malicious.json"
    sync = OpenSsfMaliciousSync(data_path=data_path)
    
    # Passing None for ecosystem
    assert sync.get_malicious_record(None, "foo") is None
    
    # Passing None for package_name
    assert sync.get_malicious_record("npm", None) is None
    
    # Passing None for both
    assert sync.get_malicious_record(None, None) is None
    
    # Passing empty string for ecosystem
    assert sync.get_malicious_record("", "foo") is None
    
    # Passing empty string for package_name
    assert sync.get_malicious_record("npm", "") is None

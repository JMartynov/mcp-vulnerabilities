"""
Unit tests for Security Picture and Drift Differ (Task 115).
"""

import pytest
from pathlib import Path
from mcp_vulnerabilities.audit.picture import SecurityPicture, SecurityServerRecord
from mcp_vulnerabilities.audit.picture_diff import SecurityPictureDiffer

def test_security_picture_serialization(tmp_path):
    p = tmp_path / "security_picture.json"
    server = SecurityServerRecord(
        server_name="test-server",
        package_name="test-server",
        version="1.0.0",
        ecosystem="npm",
        canonical_tool_hash="abc123hash",
        passport_id="passport-1",
        confirmed_cves=["CVE-2024-9999"],
        cvss_severities=[9.8],
        tamper_status=False,
        safe_upgrade_target="1.0.1"
    )
    picture = SecurityPicture(
        timestamp="2026-10-31T00:00:00Z",
        scan_target="localhost",
        total_servers=1,
        vulnerable_servers=1,
        tampered_servers=0,
        servers=[server]
    )
    saved_path = picture.save(p)
    assert saved_path.exists()

    loaded = SecurityPicture.load(p)
    assert loaded is not None
    assert loaded.total_servers == 1
    assert loaded.servers[0].package_name == "test-server"
    assert loaded.servers[0].confirmed_cves == ["CVE-2024-9999"]

def test_security_picture_differ():
    baseline_server = SecurityServerRecord(
        server_name="server-a",
        package_name="server-a",
        version="1.0.0",
        ecosystem="npm",
        canonical_tool_hash="hash1",
        passport_id="p1",
        confirmed_cves=[],
        cvss_severities=[],
        tamper_status=False
    )
    baseline = SecurityPicture(
        timestamp="2026-10-31T00:00:00Z",
        scan_target="localhost",
        total_servers=1,
        vulnerable_servers=0,
        tampered_servers=0,
        servers=[baseline_server]
    )

    current_server = SecurityServerRecord(
        server_name="server-a",
        package_name="server-a",
        version="1.0.0",
        ecosystem="npm",
        canonical_tool_hash="hash2", # changed schema hash
        passport_id="p1",
        confirmed_cves=["CVE-2026-0001"], # new vulnerability
        cvss_severities=[7.5],
        tamper_status=True # new tamper incident
    )
    current = SecurityPicture(
        timestamp="2026-10-31T01:00:00Z",
        scan_target="localhost",
        total_servers=1,
        vulnerable_servers=1,
        tampered_servers=1,
        servers=[current_server]
    )

    report = SecurityPictureDiffer.compare(baseline, current)
    assert report.is_drift_detected is True
    assert len(report.newly_introduced_vulnerabilities) == 1
    assert len(report.tamper_incidents) == 1
    assert len(report.tool_schema_changes) == 1

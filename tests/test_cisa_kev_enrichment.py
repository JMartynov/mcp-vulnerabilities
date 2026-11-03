import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from mcp_vulnerabilities.threat_intel.cisa_kev import CisaKevClient, CisaKevRecord
from mcp_vulnerabilities.models import OsvVulnerability
from mcp_vulnerabilities.audit.matcher import AuditFinding
from mcp_vulnerabilities.audit.reporters import SarifReporter

# Dummy constants
MOCK_CISA_DATA = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2026.11.01",
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-54133",
            "vendorProject": "Anthropic",
            "product": "Model Context Protocol",
            "vulnerabilityName": "MCP Improper Input Validation Vulnerability",
            "dateAdded": "2026-02-15",
            "shortDescription": "Anthropic MCP contains an improper input validation vulnerability...",
            "requiredAction": "Apply vendor mitigation or upgrade to patched version.",
            "dueDate": "2026-03-08",
            "knownRansomwareCampaignUse": "Known"
        }
    ]
}

@pytest.fixture
def kev_client(tmp_path):
    return CisaKevClient(data_dir=tmp_path)

def test_cisa_kev_client_sync_and_parse(kev_client):
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(MOCK_CISA_DATA).encode("utf-8")
        mock_resp.headers = {"ETag": '"12345"'}
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        records = kev_client.sync()

        assert "CVE-2024-54133" in records
        rec = records["CVE-2024-54133"]
        assert isinstance(rec, CisaKevRecord)
        assert rec.cve_id == "CVE-2024-54133"
        assert rec.known_ransomware_campaign_use == "Known"

        # Verify it checks ETag
        assert kev_client.meta_file.exists()

def test_cisa_kev_etag_304_cache_hit(kev_client):
    # First sync to populate cache
    kev_client.cache_file.write_text(json.dumps(MOCK_CISA_DATA), encoding="utf-8")
    kev_client.meta_file.write_text(json.dumps({"etag": '"12345"', "last_modified": "Wed, 21 Oct 2015 07:28:00 GMT"}), encoding="utf-8")

    from urllib.error import HTTPError
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = HTTPError(url="", code=304, msg="Not Modified", hdrs=None, fp=None)

        records = kev_client.sync()

        assert "CVE-2024-54133" in records
        assert kev_client.is_known_exploited("CVE-2024-54133") is True

def test_cisa_kev_offline_fallback(kev_client):
    kev_client.cache_file.write_text(json.dumps(MOCK_CISA_DATA), encoding="utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = Exception("Network offline")

        records = kev_client.sync()
        assert "CVE-2024-54133" in records

def test_pipeline_kev_enrichment(kev_client):
    kev_client.cache_file.write_text(json.dumps(MOCK_CISA_DATA), encoding="utf-8")
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = Exception("offline")
        records = kev_client.sync()
    assert records

    mock_osv = OsvVulnerability.from_dict({
        "id": "CVE-2024-54133",
        "summary": "Mock vulnerability",
        "details": "Mock details"
    })

    adv = mock_osv
    kev_record = kev_client.get_record(adv.id)
    if kev_record:
        if "cisa_kev" not in adv.database_specific:
            adv.database_specific["is_cisa_kev"] = True
            adv.database_specific["cisa_kev_date_added"] = kev_record.date_added
            adv.database_specific["cisa_kev_due_date"] = kev_record.due_date

        if adv.threat_intelligence is None:
            object.__setattr__(adv, "threat_intelligence", {})

        adv.threat_intelligence["cisa_kev"] = {
            "known_exploited": True,
            "date_added": kev_record.date_added,
            "due_date": kev_record.due_date,
            "ransomware_use": kev_record.known_ransomware_campaign_use,
            "required_action": kev_record.required_action,
        }

    assert adv.threat_intelligence["cisa_kev"]["known_exploited"] is True
    assert adv.database_specific["is_cisa_kev"] is True

def test_composite_risk_kev_elevation():
    from mcp_vulnerabilities.site_builder import _compute_composite_risk
    # normal risk
    sev, tier = _compute_composite_risk("LOW", True, [
        {"is_vulnerable": True, "advisories": [{"database_specific": {"severity": "LOW"}}]}
    ])
    assert tier != "CRITICAL"

    class DummyAdv:
        def __init__(self, **kwargs):
            self.database_specific = kwargs

    # KEV elevated risk
    sev, tier = _compute_composite_risk("LOW", True, [
        {"is_vulnerable": True, "advisories": [DummyAdv(severity="LOW", is_cisa_kev=True)]}
    ])
    assert tier == "CRITICAL"
    assert sev == "CRITICAL"

def test_cli_audit_kev_badge_rendering(capsys):
    from mcp_vulnerabilities.cli import main
    import sys
    from mcp_vulnerabilities.audit.matcher import AuditReport, AuditFinding

    mock_report = AuditReport(scanned_servers=[], findings=[
        AuditFinding(
            server_name="test-server",
            package_name="test-pkg",
            installed_version="1.0.0",
            vulnerability_id="CVE-2024-54133",
            summary="Test summary",
            severity_level="LOW",
            cvss_score=4.3,
            fixed_version="1.0.1",
            affected_range="<1.0.1",
            references=[],
            is_confirmed=True,
            is_cisa_kev=True,
            cisa_kev_date_added="2026-02-15",
            cisa_kev_due_date="2026-03-08",
            cisa_kev_ransomware_campaign_use="Known",
            cisa_kev_required_action="Patch."
        )
    ])

    with patch("mcp_vulnerabilities.audit.parsers.UniversalClientConfigScanner.scan_all_clients", return_value=[]), \
         patch("mcp_vulnerabilities.audit.parsers.ClientConfigParser.parse_file", return_value=[]), \
         patch("mcp_vulnerabilities.audit.matcher.VulnerabilityMatcher.audit_servers", return_value=mock_report):

        sys.argv = ["mcp-vuln", "audit", "--config", "mock.json"]

        try:
            main()
        except SystemExit:
            pass

    captured = capsys.readouterr()
    assert "[🚨 CISA KEV: ACTIVELY EXPLOITED IN THE WILD]" in captured.out

def test_sarif_reporter_kev_properties():
    finding = AuditFinding(
        server_name="test-server",
        package_name="test-pkg",
        installed_version="1.0.0",
        vulnerability_id="CVE-2024-54133",
        summary="Test summary",
        severity_level="LOW",
        cvss_score=4.3,
        fixed_version="1.0.1",
        affected_range="<1.0.1",
        references=[],
        is_confirmed=True,
        is_cisa_kev=True,
        cisa_kev_date_added="2026-02-15",
        cisa_kev_due_date="2026-03-08",
        cisa_kev_ransomware_campaign_use="Known",
        cisa_kev_required_action="Patch."
    )

    from mcp_vulnerabilities.audit.matcher import AuditReport
    report = AuditReport(scanned_servers=[], findings=[finding])
    sarif_doc = SarifReporter.generate_audit_sarif(report)

    rule = sarif_doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["cisaKev"] is True
    assert "actively-exploited" in rule["properties"]["tags"]

    res = sarif_doc["runs"][0]["results"][0]
    assert res["level"] == "error"

def test_web_portal_kev_badge_rendering():
    app_js_path = Path("docs/app.js")
    content = app_js_path.read_text(encoding="utf-8")

    assert "badge-cisa-kev" in content
    assert "has_active_kev_exploit" in content
    assert "CISA Known Exploited Vulnerability" in content

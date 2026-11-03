import sys
from unittest.mock import MagicMock
if "mcp_fingerprints" not in sys.modules:
    try:
        import mcp_fingerprints
    except ImportError:
        sys.modules["mcp_fingerprints"] = MagicMock()
        sys.modules["mcp_fingerprints.models"] = MagicMock()
        sys.modules["mcp_fingerprints.config_scanner"] = MagicMock()
        sys.modules["mcp_fingerprints.matchers"] = MagicMock()
import json
import os
import pytest
from unittest.mock import patch, MagicMock
from mcp_vulnerabilities.threat_intel.epss import EpssClient, EpssScore
from mcp_vulnerabilities.scoring import CompositeRiskScorer

@pytest.fixture
def epss_cache(tmp_path):
    cache_file = tmp_path / "epss_cache.json"
    yield str(cache_file)

def test_epss_client_bulk_batching(epss_cache):
    client = EpssClient(cache_file=epss_cache)
    cve_ids = [f"CVE-2024-{1000 + i}" for i in range(250)]

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"data": [{"cve": "dummy", "epss": 0.5, "percentile": 0.9}]}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client.get_scores(cve_ids)

        # 250 / 100 = 3 batches
        assert mock_urlopen.call_count == 3

def test_epss_cache_ttl_and_reuse(epss_cache):
    client = EpssClient(cache_file=epss_cache)

    from datetime import datetime
    with open(epss_cache, "w") as f:
        json.dump({
            "last_sync_utc": datetime.utcnow().isoformat() + "Z",
            "scores": {
                "CVE-2023-9999": {"score": 0.9, "percentile": 0.95, "date": "2024-01-01"}
            }
        }, f)

    client._cache = client._load_cache()

    with patch("urllib.request.urlopen") as mock_urlopen:
        res = client.get_scores(["CVE-2023-9999"])
        assert "CVE-2023-9999" in res
        assert mock_urlopen.call_count == 0

def test_epss_offline_fallback(epss_cache):
    client = EpssClient(cache_file=epss_cache)

    from datetime import datetime, timedelta
    stale_time = datetime.utcnow() - timedelta(hours=48)
    with open(epss_cache, "w") as f:
        json.dump({
            "last_sync_utc": stale_time.isoformat() + "Z",
            "scores": {
                "CVE-2023-8888": {"score": 0.8, "percentile": 0.85, "date": "2024-01-01"}
            }
        }, f)

    client._cache = client._load_cache()

    with patch("urllib.request.urlopen", side_effect=Exception("Offline!")):
        res = client.get_scores(["CVE-2023-8888"])
        assert "CVE-2023-8888" in res
        assert res["CVE-2023-8888"].score == 0.8

def test_scoring_composite_epss_boost():
    epss = EpssScore("CVE-0000-0000", score=0.85, percentile=0.99, date="")
    score = CompositeRiskScorer.calculate_composite_score(7.2, epss)
    assert abs(score - 7.59) < 0.001

    tier = CompositeRiskScorer.calculate_elevated_tier("MEDIUM", epss)
    assert tier == "HIGH"

def test_cli_min_epss_filter():
    import subprocess
    result = subprocess.run(["uv", "run", "mcp-vuln", "audit", "--help"], capture_output=True, text=True)
    assert "--min-epss" in result.stdout

def test_sarif_epss_properties():
    with open("src/mcp_vulnerabilities/audit/reporters.py") as f:
        content = f.read()
    assert 'rules_dict[rule_id]["properties"]["epssScore"] = finding.epss_score' in content
    assert 'rules_dict[rule_id]["properties"]["epssPercentile"] = getattr(finding, "epss_percentile"' in content

def test_web_epss_pill_classes():
    with open("docs/app.js") as f:
        content = f.read()
    assert "epss-danger" in content
    assert "epss-warning" in content
    assert "epss-low" in content
    assert "escapeHtml" in content

import json
import os
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from mcp_vulnerabilities.models import OsvVulnerability
from mcp_vulnerabilities.pipeline import McpVulnerabilityPipeline, _get_nvd_headers


class TestNvdPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = McpVulnerabilityPipeline(
            output_dir="data/vulnerabilities",
            state_file="data/vulnerabilities/sync_state.json",
        )
        self.pipeline.state_manager.state.sources.clear()

    @patch.dict(os.environ, {"NVD_API_KEY": "test_key_123"}, clear=True)
    def test_get_nvd_headers_with_key(self):
        headers = _get_nvd_headers()
        self.assertEqual(headers["apiKey"], "test_key_123")
        self.assertEqual(headers["User-Agent"], "mcp-vulnerabilities-ingest/1.0")

    @patch.dict(os.environ, clear=True)
    def test_get_nvd_headers_without_key(self):
        headers = _get_nvd_headers()
        self.assertNotIn("apiKey", headers)

    @patch("urllib.request.urlopen")
    @patch("time.sleep")
    def test_sync_nvd_api_success(self, mock_sleep, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2024-01-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "published": "2024-01-01T00:00:00Z",
                        "lastModified": "2024-01-01T00:00:00Z",
                        "descriptions": [
                            {"lang": "en", "value": "A vulnerability in modelcontextprotocol mcp server allowing RCE."}
                        ],
                    }
                }
            ]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        results = self.pipeline._sync_nvd_api(keywords=("mcp server",), results_per_page=1)
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], OsvVulnerability)
        self.assertEqual(results[0].id, "CVE-2024-1234")

    @patch("urllib.request.urlopen")
    @patch("time.sleep")
    def test_sync_nvd_api_rate_limit(self, mock_sleep, mock_urlopen):
        mock_error = urllib.error.HTTPError(
            url="http://test.com", code=429, msg="Too Many Requests", hdrs={}, fp=None
        )
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-5678",
                        "published": "2024-01-01T00:00:00Z",
                        "lastModified": "2024-01-01T00:00:00Z",
                        "descriptions": [
                            {"lang": "en", "value": "Model context protocol issue."}
                        ],
                    }
                }
            ]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        
        # Fail first with 429, then succeed
        mock_urlopen.side_effect = [mock_error, mock_resp]

        results = self.pipeline._sync_nvd_api(keywords=("mcp server",), results_per_page=1)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].id, "CVE-2024-5678")
        # Ensure sleep was called for delay and backoff
        self.assertTrue(mock_sleep.call_count >= 2)

    @patch("urllib.request.urlopen")
    @patch("time.sleep")
    def test_sync_nvd_api_irrelevant(self, mock_sleep, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-9999",
                        "published": "2024-01-01T00:00:00Z",
                        "lastModified": "2024-01-01T00:00:00Z",
                        "descriptions": [
                            {"lang": "en", "value": "A random bug in unrelated software."}
                        ],
                    }
                }
            ]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        results = self.pipeline._sync_nvd_api(keywords=("mcp server",), results_per_page=1)
        self.assertEqual(len(results), 0)

if __name__ == "__main__":
    unittest.main()

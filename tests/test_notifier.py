"""Unit tests for webhook dispatcher."""

import os
import urllib.request
from unittest.mock import patch

from mcp_vulnerabilities.notifier import ThreatFeedNotifier


def test_notifier_skips_when_no_urls_configured():
    with patch.dict(os.environ, {}, clear=True):
        notifier = ThreatFeedNotifier()
        with patch.object(notifier, '_send_webhook') as mock_send:
            notifier.process_and_notify([{"id": "GHSA-1", "database_specific": {"severity": "CRITICAL"}}])
            mock_send.assert_not_called()


def test_notifier_filters_low_severity():
    with patch.dict(os.environ, {"DISCORD_WEBHOOK_URL": "http://discord.test"}):
        notifier = ThreatFeedNotifier()
        with patch.object(notifier, '_send_webhook') as mock_send:
            # Should be skipped (no CRITICAL/HIGH, no cvss >= 7)
            notifier.process_and_notify([{"id": "GHSA-1", "database_specific": {"severity": "LOW", "cvss_score": 3.0}}])
            mock_send.assert_not_called()


def test_notifier_dispatches_discord_high_severity():
    with patch.dict(os.environ, {"DISCORD_WEBHOOK_URL": "http://discord.test"}, clear=True):
        notifier = ThreatFeedNotifier()
        with patch.object(urllib.request, 'urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.status = 204
            
            adv = {
                "id": "GHSA-critical-1",
                "summary": "Test Summary",
                "database_specific": {
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "vulnerable_tools": ["toolA"]
                }
            }
            notifier.process_and_notify([adv])
            
            # verify call
            assert mock_urlopen.called
            req = mock_urlopen.call_args[0][0]
            assert req.full_url == "http://discord.test"
            
            # verify payload structure
            import json
            payload = json.loads(req.data.decode("utf-8"))
            assert "embeds" in payload
            embed = payload["embeds"][0]
            assert "[CRITICAL] GHSA-critical-1: Test Summary" in embed["title"]
            
            # verify tools are present in fields
            fields = embed["fields"]
            tools_field = next(f for f in fields if f["name"] == "Vulnerable Tools")
            assert tools_field["value"] == "toolA"


def test_notifier_dispatches_slack_high_severity():
    with patch.dict(os.environ, {"SLACK_WEBHOOK_URL": "http://slack.test"}, clear=True):
        notifier = ThreatFeedNotifier()
        with patch.object(urllib.request, 'urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.status = 200
            
            adv = {
                "id": "CVE-2024-9999",
                "summary": "Slack Test Summary",
                "severity": [{"type": "CVSS_V3", "score": "7.5"}] # High severity based on cvss_score >= 7.0
            }
            notifier.process_and_notify([adv])
            
            assert mock_urlopen.called
            req = mock_urlopen.call_args[0][0]
            assert req.full_url == "http://slack.test"
            
            import json
            payload = json.loads(req.data.decode("utf-8"))
            assert "blocks" in payload
            # Slack uses emoji for severity
            header = payload["blocks"][0]
            assert "Alert: CVE-2024-9999" in header["text"]["text"]

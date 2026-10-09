"""Webhook dispatcher for real-time Threat Feed notifications."""

import json
import logging
import os
import urllib.request
import urllib.error
from typing import Any

from mcp_vulnerabilities.feed import AdvisoryFeedBuilder

logger = logging.getLogger(__name__)

class ThreatFeedNotifier:
    """Dispatches webhook notifications for CRITICAL and HIGH severity advisories."""

    def __init__(self):
        self.discord_url = os.environ.get("DISCORD_WEBHOOK_URL")
        self.slack_url = os.environ.get("SLACK_WEBHOOK_URL")

    def process_and_notify(self, advisories: list[dict[str, Any]]) -> None:
        """Filter advisories and dispatch webhooks for critical/high issues."""
        if not self.discord_url and not self.slack_url:
            logger.debug("No webhook URLs configured, skipping notifications.")
            return

        for adv in advisories:
            severity, cvss = AdvisoryFeedBuilder._extract_severity_info(adv)
            
            # Check if severity is CRITICAL or HIGH, or if CVSS score >= 7.0
            is_high_severity = severity in ("CRITICAL", "HIGH")
            if not is_high_severity and cvss is not None and cvss >= 7.0:
                is_high_severity = True

            if is_high_severity:
                logger.info(f"Dispatching notification for high-severity advisory {adv.get('id')}")
                if self.discord_url:
                    self._notify_discord(adv, severity, cvss)
                if self.slack_url:
                    self._notify_slack(adv, severity, cvss)

    def _notify_discord(self, adv: dict[str, Any], severity: str, cvss: float | None) -> None:
        """Format and send Discord webhook."""
        adv_id = adv.get("id", "UNKNOWN")
        summary = adv.get("summary") or adv.get("details", "")[:140]
        url = AdvisoryFeedBuilder._extract_canonical_url(adv)
        
        # Color based on severity
        color = 16711680 if severity == "CRITICAL" else 16753920 # Red or Orange
        
        # Extract vulnerable tools and remediation
        db_spec = adv.get("database_specific", {})
        if not db_spec and adv.get("affected"):
            db_spec = adv["affected"][0].get("database_specific", {})
            
        vulnerable_tools = db_spec.get("vulnerable_tools", [])
        tools_str = ", ".join(vulnerable_tools) if vulnerable_tools else "Unknown"
        remediation = db_spec.get("remediation_guidance", "See advisory link for details.")

        cvss_str = str(cvss) if cvss is not None else "N/A"

        payload = {
            "embeds": [{
                "title": f"[{severity}] {adv_id}: {summary}",
                "url": url,
                "color": color,
                "fields": [
                    {"name": "CVSS Score", "value": cvss_str, "inline": True},
                    {"name": "Vulnerable Tools", "value": tools_str, "inline": True},
                    {"name": "Remediation", "value": remediation, "inline": False}
                ],
                "footer": {"text": "MCP Security Advisory"}
            }]
        }

        self._send_webhook(self.discord_url, payload, "Discord")

    def _notify_slack(self, adv: dict[str, Any], severity: str, cvss: float | None) -> None:
        """Format and send Slack incoming webhook."""
        adv_id = adv.get("id", "UNKNOWN")
        summary = adv.get("summary") or adv.get("details", "")[:140]
        url = AdvisoryFeedBuilder._extract_canonical_url(adv)
        
        cvss_str = str(cvss) if cvss is not None else "N/A"
        
        # Determine emoji based on severity
        emoji = "🚨" if severity == "CRITICAL" else "⚠️"
        
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} {severity} Severity Alert: {adv_id}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{summary}*\nCVSS Score: {cvss_str}\n<{url}|View CVE Details>"
                    }
                }
            ]
        }

        self._send_webhook(self.slack_url, payload, "Slack")

    def _send_webhook(self, url: str, payload: dict, platform: str) -> None:
        """Helper to send JSON payload via HTTP POST with timeout."""
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "mcp-vulnerabilities/1.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status not in (200, 201, 204):
                    logger.error(f"Failed to notify {platform}: HTTP {response.status}")
        except urllib.error.URLError as e:
            logger.error(f"Network error notifying {platform}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error notifying {platform}: {e}")

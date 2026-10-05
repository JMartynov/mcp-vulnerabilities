"""Glama.ai registry discovery provider for Model Context Protocol servers."""

from __future__ import annotations

import json
import logging
import os
import ssl
import urllib.request
from typing import Any

from mcp_vulnerabilities.filter import McpRelevanceFilter

logger = logging.getLogger("mcp_vulnerabilities.discovery.glama")


def _get_ssl_context() -> ssl.SSLContext:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return ssl._create_unverified_context()


class GlamaDiscoveryProvider:
    """Discovers MCP servers cataloged on Glama.ai."""

    BASE_URL = "https://glama.ai/api/mcp/v1/servers"

    @classmethod
    def discover(cls, api_key: str | None = None) -> list[dict[str, Any]]:
        """Queries Glama API for registered MCP servers if credentials are provided."""
        token = api_key or os.environ.get("GLAMA_API_KEY")
        if not token:
            logger.info("Glama discovery skipped (GLAMA_API_KEY environment variable not configured)")
            return []

        headers = {
            "User-Agent": "McpVulnerabilities/1.0",
            "Accept": "application/json",
            "X-API-Key": token,
            "Authorization": f"Bearer {token}",
        }

        req = urllib.request.Request(cls.BASE_URL, headers=headers)
        discovered: list[dict[str, Any]] = []

        try:
            with urllib.request.urlopen(req, timeout=12.0, context=_get_ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                servers = data.get("servers", data.get("items", []))
                for s in servers:
                    slug = s.get("slug") or s.get("id")
                    if not slug:
                        continue
                    namespace = s.get("namespace", "glama")
                    full_name = f"{namespace}/{slug}"
                    desc = s.get("description", "")
                    repo = s.get("repositoryUrl") or s.get("homepage")

                    discovered.append({
                        "name": f"@glama/{full_name}",
                        "ecosystem": "glama",
                        "version": s.get("version", "1.0.0"),
                        "description": desc[:300] if desc else None,
                        "repository": repo,
                        "registry_url": f"https://glama.ai/mcp/servers/{namespace}/{slug}",
                        "relevance_score": 0.90,
                    })

        except Exception as exc:
            logger.warning("Glama discovery error: %s", exc)

        return discovered

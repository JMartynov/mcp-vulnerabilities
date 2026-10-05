"""PyPI Registry discovery provider for MCP servers using PEP 691 JSON API."""

from __future__ import annotations

import json
import logging
import ssl
import urllib.request
from typing import Any

from mcp_vulnerabilities.filter import McpRelevanceFilter

logger = logging.getLogger("mcp_vulnerabilities.discovery.pypi")


def _get_ssl_context() -> ssl.SSLContext:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return ssl._create_unverified_context()


class PypiDiscoveryProvider:
    """Discovers Model Context Protocol packages on PyPI via PEP 691 JSON Simple API."""

    @classmethod
    def discover(cls, timeout: float = 15.0) -> list[dict[str, Any]]:
        """Fetch and filter PyPI index for canonical MCP servers."""
        url = "https://pypi.org/simple/"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.pypi.simple.v1+json",
                "User-Agent": "McpVulnerabilities/1.0",
            },
        )
        discovered: list[dict[str, Any]] = []
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_get_ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                projects = data.get("projects", [])
                for p in projects:
                    name = p.get("name", "")
                    norm = name.lower()
                    if (
                        norm.startswith("mcp-server-")
                        or norm.startswith("mcp-")
                        or norm.endswith("-mcp-server")
                        or norm.endswith("-mcp")
                        or "mcp_server" in norm
                        or norm in ("mcp", "fastmcp")
                    ):
                        is_rel, reasons = McpRelevanceFilter.is_relevant(package_name=name)
                        if is_rel:
                            discovered.append({
                                "name": name,
                                "ecosystem": "PyPI",
                                "version": "",  # PyPI simple doesn't supply version without extra call; version resolved on audit
                                "reasons": list(reasons),
                            })
        except Exception as exc:
            logger.warning("PyPI PEP 691 discovery failed: %s", exc)

        return discovered

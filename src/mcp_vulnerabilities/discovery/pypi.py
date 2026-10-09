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
    def resolve_package_version(cls, name: str, timeout: float = 5.0) -> str:
        """Resolve the latest version of a PyPI package using the JSON API."""
        url = f"https://pypi.org/pypi/{name}/json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "McpVulnerabilities/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_get_ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("info", {}).get("version", "")
        except Exception as exc:
            logger.warning("Failed to resolve version for %s: %s", name, exc)
            return ""

    @classmethod
    def enrich_package_version(cls, package: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
        """Populate package version using resolve_package_version if not already present."""
        if not package.get("version"):
            package["version"] = cls.resolve_package_version(package["name"], timeout=timeout)
        return package

    @classmethod
    def discover(cls, timeout: float = 15.0, resolve_versions: bool = False) -> list[dict[str, Any]]:
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
                        norm.startswith(("mcp-server-", "mcp-")) or norm.endswith(("-mcp-server", "-mcp")) or "mcp_server" in norm or norm in ("mcp", "fastmcp")
                    ):
                        is_rel, reasons = McpRelevanceFilter.is_relevant(package_name=name)
                        if is_rel:
                            discovered.append({
                                "name": name,
                                "ecosystem": "PyPI",
                                "version": cls.resolve_package_version(name, timeout=timeout) if resolve_versions else "",
                                "reasons": list(reasons),
                            })
        except Exception as exc:
            logger.warning("PyPI PEP 691 discovery failed: %s", exc)

        return discovered

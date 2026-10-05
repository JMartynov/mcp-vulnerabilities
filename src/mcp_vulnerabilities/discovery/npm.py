"""npm Registry discovery provider for MCP servers."""

from __future__ import annotations

import json
import logging
import ssl
import urllib.parse
import urllib.request
from typing import Any

from mcp_vulnerabilities.filter import McpRelevanceFilter

logger = logging.getLogger("mcp_vulnerabilities.discovery.npm")


def _get_ssl_context() -> ssl.SSLContext:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return ssl._create_unverified_context()


class NpmDiscoveryProvider:
    """Discovers Model Context Protocol packages published on npm."""

    DEFAULT_QUERIES: tuple[str, ...] = (
        "keywords:mcp-server",
        "keywords:modelcontextprotocol",
        "text=@modelcontextprotocol",
        "mcp-server",
    )

    @classmethod
    def discover(cls, queries: tuple[str, ...] | None = None, limit_per_query: int = 250) -> list[dict[str, Any]]:
        """Query npm registry search API and return verified MCP server metadata."""
        search_terms = queries or cls.DEFAULT_QUERIES
        discovered: dict[str, dict[str, Any]] = {}

        for q in search_terms:
            url = f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(q)}&size={limit_per_query}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "McpVulnerabilities/1.0", "Accept": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=12.0, context=_get_ssl_context()) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    for obj in data.get("objects", []):
                        pkg = obj.get("package", {})
                        name = pkg.get("name")
                        if not name or name in discovered:
                            continue

                        desc = pkg.get("description", "")
                        repo = pkg.get("links", {}).get("repository")
                        version = pkg.get("version", "1.0.0")

                        is_rel, reasons = McpRelevanceFilter.is_relevant(
                            package_name=name,
                            summary=desc,
                            details=desc,
                            repo_url=repo,
                        )
                        if is_rel:
                            discovered[name] = {
                                "name": name,
                                "ecosystem": "npm",
                                "version": version,
                                "description": desc,
                                "repository": repo,
                                "reasons": list(reasons),
                            }
            except Exception as exc:
                logger.warning("npm discovery query '%s' failed: %s", q, exc)

        return list(discovered.values())

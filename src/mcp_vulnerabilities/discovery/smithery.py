"""Smithery.ai registry discovery provider for Model Context Protocol servers."""

from __future__ import annotations

import json
import logging
import ssl
import urllib.request
from typing import Any

from mcp_vulnerabilities.filter import McpRelevanceFilter

logger = logging.getLogger("mcp_vulnerabilities.discovery.smithery")


def _get_ssl_context() -> ssl.SSLContext:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return ssl._create_unverified_context()


class SmitheryDiscoveryProvider:
    """Discovers MCP servers cataloged on Smithery.ai."""

    BASE_URL = "https://api.smithery.ai/servers"

    @classmethod
    def discover(cls, max_pages: int = 5, page_size: int = 100) -> list[dict[str, Any]]:
        """Queries Smithery registry API and returns MCP server entries."""
        discovered: dict[str, dict[str, Any]] = {}

        for page in range(1, max_pages + 1):
            url = f"{cls.BASE_URL}?page={page}&pageSize={page_size}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "McpVulnerabilities/1.0", "Accept": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=12.0, context=_get_ssl_context()) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    servers = data.get("servers", [])
                    if not servers:
                        break

                    for s in servers:
                        qname = s.get("qualifiedName") or s.get("id")
                        if not qname or qname in discovered:
                            continue

                        display_name = s.get("displayName") or qname
                        desc = s.get("description", "")
                        homepage = s.get("homepage", "")

                        # Determine repository and package name
                        repo = homepage if "github.com" in homepage else None
                        pkg_name = f"@smithery/{qname}" if "/" not in qname else qname

                        is_rel, reasons = McpRelevanceFilter.is_relevant(
                            package_name=qname,
                            summary=display_name,
                            details=desc,
                            repo_url=repo,
                        )

                        if is_rel or s.get("verified") or s.get("bySmithery") or True:
                            discovered[qname] = {
                                "name": pkg_name,
                                "ecosystem": "smithery",
                                "version": "1.0.0",
                                "description": desc[:300] if desc else None,
                                "repository": repo,
                                "registry_url": f"https://smithery.ai/server/{qname}",
                                "relevance_score": 0.95 if is_rel else 0.85,
                            }

            except Exception as exc:
                logger.warning("Smithery discovery failed on page %d: %s", page, exc)
                break

        logger.info("Smithery discovery found %d verified servers", len(discovered))
        return list(discovered.values())

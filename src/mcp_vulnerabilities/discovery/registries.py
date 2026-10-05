"""Multi-ecosystem registry discovery provider (crates.io, RubyGems, Docker Hub)."""

from __future__ import annotations

import json
import logging
import ssl
import urllib.request
from typing import Any

from mcp_vulnerabilities.filter import McpRelevanceFilter

logger = logging.getLogger("mcp_vulnerabilities.discovery.registries")


def _get_ssl_context() -> ssl.SSLContext:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return ssl._create_unverified_context()


class MultiRegistryDiscoveryProvider:
    """Discovers MCP packages across crates.io, RubyGems, and Docker Hub."""

    @classmethod
    def discover_crates_io(cls) -> list[dict[str, Any]]:
        """Harvest Rust MCP crates from crates.io."""
        discovered: list[dict[str, Any]] = []
        url = "https://crates.io/api/v1/crates?q=mcp&per_page=100"
        req = urllib.request.Request(url, headers={"User-Agent": "McpVulnerabilities/1.0 (Security Research)"})
        try:
            with urllib.request.urlopen(req, timeout=8.0, context=_get_ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for c in data.get("crates", []):
                    name = c.get("id")
                    desc = c.get("description", "")
                    ver = c.get("max_version", "")
                    is_rel, reasons = McpRelevanceFilter.is_relevant(package_name=name, summary=desc, details=desc)
                    if is_rel:
                        discovered.append({
                            "name": name,
                            "ecosystem": "crates.io",
                            "version": ver,
                            "description": desc,
                            "reasons": list(reasons),
                        })
        except Exception as exc:
            logger.warning("crates.io discovery failed: %s", exc)
        return discovered

    @classmethod
    def discover_rubygems(cls) -> list[dict[str, Any]]:
        """Harvest Ruby MCP gems from RubyGems."""
        discovered: list[dict[str, Any]] = []
        url = "https://rubygems.org/api/v1/search.json?query=mcp"
        req = urllib.request.Request(url, headers={"User-Agent": "McpVulnerabilities/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=8.0, context=_get_ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if isinstance(data, list):
                    for g in data:
                        name = g.get("name")
                        desc = g.get("info", "")
                        ver = g.get("version", "")
                        is_rel, reasons = McpRelevanceFilter.is_relevant(package_name=name, summary=desc, details=desc)
                        if is_rel:
                            discovered.append({
                                "name": name,
                                "ecosystem": "RubyGems",
                                "version": ver,
                                "description": desc,
                                "reasons": list(reasons),
                            })
        except Exception as exc:
            logger.warning("RubyGems discovery failed: %s", exc)
        return discovered

    @classmethod
    def discover_docker_hub(cls) -> list[dict[str, Any]]:
        """Harvest containerized MCP servers from Docker Hub."""
        discovered: list[dict[str, Any]] = []
        url = "https://hub.docker.com/v2/search/repositories/?query=mcp-server&page_size=100"
        req = urllib.request.Request(url, headers={"User-Agent": "McpVulnerabilities/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=8.0, context=_get_ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for r in data.get("results", []):
                    name = r.get("repo_name")
                    desc = r.get("short_description", "")
                    is_rel, reasons = McpRelevanceFilter.is_relevant(package_name=name, summary=desc, details=desc)
                    if is_rel:
                        discovered.append({
                            "name": name,
                            "ecosystem": "Docker",
                            "version": "latest",
                            "description": desc,
                            "reasons": list(reasons),
                        })
        except Exception as exc:
            logger.warning("Docker Hub discovery failed: %s", exc)
        return discovered

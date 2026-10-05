"""GitHub Curated lists & Topic discovery provider for MCP servers."""

from __future__ import annotations

import json
import logging
import re
import ssl
import urllib.request
from typing import Any

from mcp_vulnerabilities.filter import McpRelevanceFilter

logger = logging.getLogger("mcp_vulnerabilities.discovery.github_curated")


def _get_ssl_context() -> ssl.SSLContext:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return ssl._create_unverified_context()


class GitHubCuratedDiscoveryProvider:
    """Discovers MCP servers from curated Awesome-lists and GitHub Topic APIs."""

    AWESOME_URLS: tuple[str, ...] = (
        "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md",
        "https://raw.githubusercontent.com/wong2/awesome-mcp-servers/main/README.md",
    )

    LINK_REGEX = re.compile(r"\[([^\]]+)\]\((https://github\.com/[^/)]+/[^/)]+)\)")

    @classmethod
    def discover(cls) -> list[dict[str, Any]]:
        """Harvest curated repositories and topics."""
        discovered: dict[str, dict[str, Any]] = {}

        # 1. Awesome Lists
        for url in cls.AWESOME_URLS:
            req = urllib.request.Request(url, headers={"User-Agent": "McpVulnerabilities/1.0"})
            try:
                with urllib.request.urlopen(req, timeout=10.0, context=_get_ssl_context()) as resp:
                    text = resp.read().decode("utf-8")
                    for title, repo in cls.LINK_REGEX.findall(text):
                        if any(x in repo.lower() for x in ("/actions", "/topics", "awesome-mcp")):
                            continue
                        repo_name = repo.split("https://github.com/")[-1].strip("/")
                        is_rel, reasons = McpRelevanceFilter.is_relevant(
                            package_name=title,
                            summary=f"Curated MCP server: {title}",
                            repo_url=repo,
                        )
                        if is_rel and repo_name not in discovered:
                            discovered[repo_name] = {
                                "name": repo_name,
                                "ecosystem": "GitHub",
                                "repository": repo,
                                "title": title,
                                "reasons": list(reasons),
                            }
            except Exception as exc:
                logger.warning("Failed to fetch awesome list %s: %s", url, exc)

        # 2. GitHub Topic Search
        topic_url = "https://api.github.com/search/repositories?q=topic:mcp-server&per_page=100&sort=stars"
        req = urllib.request.Request(
            topic_url,
            headers={
                "User-Agent": "McpVulnerabilities/1.0",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10.0, context=_get_ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for it in data.get("items", []):
                    full_name = it.get("full_name")
                    if not full_name or full_name in discovered:
                        continue
                    html_url = it.get("html_url")
                    desc = it.get("description") or ""
                    is_rel, reasons = McpRelevanceFilter.is_relevant(
                        package_name=full_name,
                        summary=desc,
                        repo_url=html_url,
                    )
                    if is_rel:
                        discovered[full_name] = {
                            "name": full_name,
                            "ecosystem": "GitHub",
                            "repository": html_url,
                            "description": desc,
                            "stars": it.get("stargazers_count", 0),
                            "reasons": list(reasons),
                        }
        except Exception as exc:
            logger.warning("GitHub topic search failed: %s", exc)

        return list(discovered.values())

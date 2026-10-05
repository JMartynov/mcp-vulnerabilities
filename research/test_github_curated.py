"""Empirical research test: GitHub Curated Repositories & Topic Discovery."""

from __future__ import annotations

import re
import time
from typing import Any

from mcp_vulnerabilities.filter import McpRelevanceFilter
from research.common import ResearchMetric, fetch_json, fetch_text, logger


def test_github_curated() -> tuple[ResearchMetric, list[dict[str, Any]]]:
    """Empirically test extraction of MCP servers from curated lists and GitHub Topics."""
    discovered: dict[str, dict[str, Any]] = {}
    total_scanned = 0
    errors = 0
    rate_limited = False
    start_t = time.perf_counter()

    # 1. Awesome MCP Servers Raw Markdown
    awesome_urls = [
        "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md",
        "https://raw.githubusercontent.com/wong2/awesome-mcp-servers/main/README.md",
    ]

    link_pattern = re.compile(r"\[([^\]]+)\]\((https://github\.com/[^/)]+/[^/)]+)\)")

    for a_url in awesome_urls:
        try:
            logger.info("Fetching curated list from: %s", a_url)
            text = fetch_text(a_url, timeout=10.0)
            matches = link_pattern.findall(text)
            total_scanned += len(matches)

            for title, repo in matches:
                # filter out obvious non-server repos like github stars, twitter, etc.
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
                        "title": title,
                        "repository": repo,
                        "reasons": list(reasons),
                        "source": "awesome-mcp-list",
                    }
        except Exception as exc:
            logger.warning("Error fetching awesome list %s: %s", a_url, exc)
            errors += 1

    # 2. GitHub Topic Search API (unauthenticated)
    topic_url = "https://api.github.com/search/repositories?q=topic:mcp-server&per_page=100&sort=stars"
    try:
        logger.info("Querying GitHub Topic Search API (topic:mcp-server)")
        data = fetch_json(topic_url, timeout=10.0)
        items = data.get("items", [])
        total_scanned += len(items)

        for it in items:
            full_name = it.get("full_name")
            desc = it.get("description") or ""
            html_url = it.get("html_url")
            stars = it.get("stargazers_count", 0)

            is_rel, reasons = McpRelevanceFilter.is_relevant(
                package_name=full_name,
                summary=desc,
                repo_url=html_url,
            )
            if is_rel and full_name not in discovered:
                discovered[full_name] = {
                    "name": full_name,
                    "ecosystem": "GitHub",
                    "title": it.get("name"),
                    "repository": html_url,
                    "stars": stars,
                    "description": desc,
                    "reasons": list(reasons),
                    "source": "github-topic-search",
                }
    except Exception as exc:
        logger.warning("Error querying GitHub Search API: %s", exc)
        errors += 1
        if "403" in str(exc) or "429" in str(exc):
            rate_limited = True

    duration = time.perf_counter() - start_t
    metric = ResearchMetric(
        method_name="github_curated_and_topics",
        target_source="Awesome MCP Lists & GitHub Topics API",
        items_scanned=total_scanned,
        mcp_items_identified=len(discovered),
        vulnerabilities_found=0,
        duration_seconds=duration,
        error_count=errors,
        rate_limit_encountered=rate_limited,
        notes=f"Identified {len(discovered)} MCP server repositories from {total_scanned} entries.",
    )
    return metric, list(discovered.values())


if __name__ == "__main__":
    metric, repos = test_github_curated()
    print(f"--- GitHub Curated Discovery Results ---")
    print(f"Total entries scanned: {metric.items_scanned}")
    print(f"MCP server repos verified: {metric.mcp_items_identified}")
    print(f"Duration: {metric.duration_seconds:.2f}s")
    print(f"Sample repos (first 10):")
    for r in repos[:10]:
        print(f"  - {r['name']} (Stars: {r.get('stars', 'N/A')}): {r.get('repository')}")

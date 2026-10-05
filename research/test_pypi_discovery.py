"""Empirical research test: PyPI MCP Server Discovery."""

from __future__ import annotations

import re
import time
import urllib.parse
from typing import Any

from mcp_vulnerabilities.filter import McpRelevanceFilter
from research.common import ResearchMetric, fetch_json, fetch_text, logger


def test_pypi_discovery() -> tuple[ResearchMetric, list[dict[str, Any]]]:
    """Empirically test discovery of MCP packages on PyPI."""
    queries = ["mcp-server", "model-context-protocol", "fastmcp"]
    discovered: dict[str, dict[str, Any]] = {}
    total_scanned = 0
    errors = 0
    rate_limited = False
    start_t = time.perf_counter()

    package_snippet_pattern = re.compile(
        r'<a class="package-snippet" href="/project/([^/]+)/".*?'
        r'<span class="package-snippet__name">([^<]+)</span>.*?'
        r'<span class="package-snippet__version">([^<]+)</span>.*?'
        r'<p class="package-snippet__description">([^<]*)</p>',
        re.DOTALL,
    )

    for q in queries:
        for page in (1, 2):
            url = f"https://pypi.org/search/?q={urllib.parse.quote(q)}&page={page}"
            try:
                logger.info("Scraping PyPI search: q=%s, page=%d", q, page)
                html = fetch_text(url, timeout=12.0)
                matches = package_snippet_pattern.findall(html)
                total_scanned += len(matches)

                for slug, name, version, desc in matches:
                    name = name.strip()
                    desc = desc.strip()
                    is_rel, reasons = McpRelevanceFilter.is_relevant(
                        package_name=name,
                        summary=desc,
                        details=desc,
                    )
                    if is_rel and name not in discovered:
                        discovered[name] = {
                            "name": name,
                            "ecosystem": "PyPI",
                            "version": version.strip(),
                            "description": desc,
                            "reasons": list(reasons),
                        }
            except Exception as exc:
                logger.warning("Error fetching PyPI search for '%s': %s", q, exc)
                errors += 1
                if "429" in str(exc):
                    rate_limited = True

    duration = time.perf_counter() - start_t
    metric = ResearchMetric(
        method_name="pypi_search_discovery",
        target_source="PyPI Search Index (pypi.org/search)",
        items_scanned=total_scanned,
        mcp_items_identified=len(discovered),
        vulnerabilities_found=0,
        duration_seconds=duration,
        error_count=errors,
        rate_limit_encountered=rate_limited,
        notes=f"Identified {len(discovered)} MCP packages from {total_scanned} PyPI search results.",
    )
    return metric, list(discovered.values())


if __name__ == "__main__":
    metric, pkgs = test_pypi_discovery()
    print(f"--- PyPI Discovery Results ---")
    print(f"Total results scanned: {metric.items_scanned}")
    print(f"MCP packages verified: {metric.mcp_items_identified}")
    print(f"Duration: {metric.duration_seconds:.2f}s")
    print(f"Sample packages (first 10):")
    for p in pkgs[:10]:
        print(f"  - {p['name']} ({p['ecosystem']}): {p['description'][:60]}")

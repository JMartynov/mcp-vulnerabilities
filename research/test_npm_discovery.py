"""Empirical research test: npm Registry MCP Server Discovery."""

from __future__ import annotations

import time
import urllib.parse
from typing import Any

from mcp_vulnerabilities.filter import McpRelevanceFilter
from research.common import ResearchMetric, fetch_json, logger


def test_npm_discovery() -> tuple[ResearchMetric, list[dict[str, Any]]]:
    """Empirically test discovery of MCP servers via npm registry search API."""
    queries = [
        "keywords:mcp-server",
        "keywords:modelcontextprotocol",
        "scope:modelcontextprotocol",
        "mcp-server",
    ]

    discovered: dict[str, dict[str, Any]] = {}
    total_scanned = 0
    errors = 0
    rate_limited = False
    start_t = time.perf_counter()

    for q in queries:
        url = f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(q)}&size=250"
        try:
            logger.info("Querying npm search API: %s", q)
            data = fetch_json(url, timeout=12.0)
            objects = data.get("objects", [])
            total_scanned += len(objects)

            for obj in objects:
                pkg = obj.get("package", {})
                name = pkg.get("name")
                desc = pkg.get("description", "")
                keywords = " ".join(pkg.get("keywords", []))
                combined = f"{desc} {keywords}"
                repo = pkg.get("links", {}).get("repository")

                is_rel, reasons = McpRelevanceFilter.is_relevant(
                    package_name=name,
                    summary=desc,
                    details=combined,
                    repo_url=repo,
                )

                if is_rel and name not in discovered:
                    discovered[name] = {
                        "name": name,
                        "ecosystem": "npm",
                        "version": pkg.get("version"),
                        "description": desc,
                        "reasons": list(reasons),
                        "repository": repo,
                    }
        except Exception as exc:
            logger.warning("Error querying npm with query '%s': %s", q, exc)
            errors += 1
            if "429" in str(exc):
                rate_limited = True

    duration = time.perf_counter() - start_t
    metric = ResearchMetric(
        method_name="npm_registry_search",
        target_source="npm Registry Search API (/v1/search)",
        items_scanned=total_scanned,
        mcp_items_identified=len(discovered),
        vulnerabilities_found=0,  # Just discovery
        duration_seconds=duration,
        error_count=errors,
        rate_limit_encountered=rate_limited,
        notes=f"Identified {len(discovered)} unique MCP packages from {total_scanned} search results.",
    )
    return metric, list(discovered.values())


if __name__ == "__main__":
    metric, pkgs = test_npm_discovery()
    print("--- npm Discovery Results ---")
    print(f"Total results scanned: {metric.items_scanned}")
    print(f"MCP packages verified: {metric.mcp_items_identified}")
    print(f"Duration: {metric.duration_seconds:.2f}s")
    print("Sample packages (first 10):")
    for p in pkgs[:10]:
        print(f"  - {p['name']} ({p['ecosystem']}): {p['description'][:60]}")

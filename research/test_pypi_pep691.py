"""Empirical research test: PyPI PEP 691 JSON Simple API Discovery."""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Any

from mcp_vulnerabilities.filter import McpRelevanceFilter
from research.common import ResearchMetric, get_ssl_context, logger


def test_pypi_pep691_discovery() -> tuple[ResearchMetric, list[dict[str, Any]]]:
    """Empirically test discovery of MCP packages via PyPI PEP 691 JSON Simple API."""
    start_t = time.perf_counter()
    url = "https://pypi.org/simple/"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.pypi.simple.v1+json",
            "User-Agent": "McpVulnerabilitiesResearch/1.0",
        },
    )

    discovered: dict[str, dict[str, Any]] = {}
    total_projects = 0
    errors = 0
    rate_limited = False

    try:
        logger.info("Fetching complete PyPI project index via PEP 691 JSON API...")
        with urllib.request.urlopen(req, timeout=15.0, context=get_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            projects = data.get("projects", [])
            total_projects = len(projects)

            for p in projects:
                name = p.get("name", "")
                norm = name.lower()
                # Fast heuristic filtering for MCP
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
                        discovered[name] = {
                            "name": name,
                            "ecosystem": "PyPI",
                            "reasons": list(reasons),
                        }
    except Exception as exc:
        logger.warning("Error fetching PyPI PEP 691 API: %s", exc)
        errors += 1
        if "429" in str(exc):
            rate_limited = True

    duration = time.perf_counter() - start_t
    metric = ResearchMetric(
        method_name="pypi_pep691_simple_api",
        target_source="PyPI PEP 691 JSON Simple Index (pypi.org/simple/)",
        items_scanned=total_projects,
        mcp_items_identified=len(discovered),
        vulnerabilities_found=0,
        duration_seconds=duration,
        error_count=errors,
        rate_limit_encountered=rate_limited,
        notes=f"Scanned {total_projects} PyPI projects in {duration:.2f}s, identified {len(discovered)} MCP packages.",
    )
    return metric, list(discovered.values())


if __name__ == "__main__":
    metric, pkgs = test_pypi_pep691_discovery()
    print("=" * 60)
    print("PyPI PEP 691 SIMPLE API BENCHMARK")
    print("=" * 60)
    print(f"Total PyPI Projects Indexed: {metric.items_scanned:,}")
    print(f"MCP Packages Identified:     {metric.mcp_items_identified:,}")
    print(f"Index Query Duration:        {metric.duration_seconds:.2f}s")
    print("Sample packages (first 10):")
    for p in pkgs[:10]:
        print(f"  - {p['name']} ({p['ecosystem']})")

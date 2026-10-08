"""Empirical research test: Multi-Registry MCP Server Discovery (crates.io, RubyGems, Docker Hub)."""

from __future__ import annotations

import time

from mcp_vulnerabilities.filter import McpRelevanceFilter
from research.common import ResearchMetric, fetch_json, logger


def test_other_registries() -> list[ResearchMetric]:
    """Empirically test discovery across crates.io (Rust), RubyGems (Ruby), and Docker Hub."""
    metrics: list[ResearchMetric] = []

    # 1. crates.io (Rust)
    t0 = time.perf_counter()
    crates_discovered = []
    try:
        data = fetch_json("https://crates.io/api/v1/crates?q=mcp&per_page=100")
        for c in data.get("crates", []):
            name = c.get("id")
            desc = c.get("description", "")
            is_rel, _ = McpRelevanceFilter.is_relevant(package_name=name, summary=desc, details=desc)
            if is_rel:
                crates_discovered.append(name)
    except Exception as e:
        logger.warning("crates.io error: %s", e)
    metrics.append(
        ResearchMetric(
            method_name="crates_io_search",
            target_source="crates.io API (Rust ecosystem)",
            items_scanned=100,
            mcp_items_identified=len(crates_discovered),
            vulnerabilities_found=0,
            duration_seconds=time.perf_counter() - t0,
            error_count=0 if crates_discovered else 1,
            rate_limit_encountered=False,
            notes=f"Identified {len(crates_discovered)} Rust MCP crates.",
        )
    )

    # 2. RubyGems
    t0 = time.perf_counter()
    gems_discovered = []
    try:
        data = fetch_json("https://rubygems.org/api/v1/search.json?query=mcp")
        for g in data:
            name = g.get("name")
            desc = g.get("info", "")
            is_rel, _ = McpRelevanceFilter.is_relevant(package_name=name, summary=desc, details=desc)
            if is_rel:
                gems_discovered.append(name)
    except Exception as e:
        logger.warning("RubyGems error: %s", e)
    metrics.append(
        ResearchMetric(
            method_name="rubygems_search",
            target_source="RubyGems API (Ruby ecosystem)",
            items_scanned=len(data) if isinstance(data, list) else 0,
            mcp_items_identified=len(gems_discovered),
            vulnerabilities_found=0,
            duration_seconds=time.perf_counter() - t0,
            error_count=0 if gems_discovered else 1,
            rate_limit_encountered=False,
            notes=f"Identified {len(gems_discovered)} Ruby MCP gems.",
        )
    )

    # 3. Docker Hub
    t0 = time.perf_counter()
    docker_discovered = []
    try:
        data = fetch_json("https://hub.docker.com/v2/search/repositories/?query=mcp-server&page_size=100")
        for r in data.get("results", []):
            name = r.get("repo_name")
            desc = r.get("short_description", "")
            is_rel, _ = McpRelevanceFilter.is_relevant(package_name=name, summary=desc, details=desc)
            if is_rel:
                docker_discovered.append(name)
    except Exception as e:
        logger.warning("Docker Hub error: %s", e)
    metrics.append(
        ResearchMetric(
            method_name="docker_hub_search",
            target_source="Docker Hub Registry API",
            items_scanned=100,
            mcp_items_identified=len(docker_discovered),
            vulnerabilities_found=0,
            duration_seconds=time.perf_counter() - t0,
            error_count=0 if docker_discovered else 1,
            rate_limit_encountered=False,
            notes=f"Identified {len(docker_discovered)} Docker Hub MCP repositories.",
        )
    )

    return metrics


if __name__ == "__main__":
    metrics = test_other_registries()
    for m in metrics:
        print(f"[{m.method_name}] Scanned: {m.items_scanned}, MCP Found: {m.mcp_items_identified}, Time: {m.duration_seconds:.2f}s ({m.notes})")

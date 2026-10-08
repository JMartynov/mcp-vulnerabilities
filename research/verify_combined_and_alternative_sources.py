"""Verification of combined static + dynamic discovery and multi-source redundancy."""

from __future__ import annotations

import time
from typing import Any

from mcp_vulnerabilities.filter import McpRelevanceFilter
from research.common import fetch_json, logger

# 1. Static seed baseline (curated, resilient)
STATIC_SEEDS: tuple[tuple[str, str], ...] = (
    ("npm", "mcp-remote"),
    ("npm", "@modelcontextprotocol/server-postgres"),
    ("npm", "@modelcontextprotocol/server-sqlite"),
    ("npm", "@modelcontextprotocol/server-filesystem"),
    ("npm", "@modelcontextprotocol/server-github"),
    ("npm", "@modelcontextprotocol/server-git"),
    ("npm", "@modelcontextprotocol/server-brave-search"),
    ("npm", "@modelcontextprotocol/sdk"),
    ("npm", "@cyanheads/git-mcp-server"),
    ("npm", "sammcj/mcp-package-docs"),
    ("npm", "@aborruso/ckan-mcp-server"),
    ("npm", "mcp-server-figma"),
    ("PyPI", "mcp"),
    ("PyPI", "fastmcp"),
    ("PyPI", "mcp-neo4j-cypher"),
    ("PyPI", "mcp-server-sqlite"),
    ("PyPI", "mcp-server-git"),
    ("PyPI", "awslabs.aws-api-mcp-server"),
    ("Go", "github.com/modelcontextprotocol/go-sdk"),
)


def verify_static_dynamic_combination() -> dict[str, Any]:
    """Verify that Static Seeds + Dynamic Discovery combine without overlap or performance degradation."""
    start_t = time.perf_counter()
    logger.info("Verifying combination of Static Seeds and Dynamic Discovery...")

    # A. Static Seeds
    static_set = {(eco.lower(), name.lower()) for eco, name in STATIC_SEEDS}

    # B. Dynamic Discovery via npm API
    dynamic_set = set()
    try:
        url = "https://registry.npmjs.org/-/v1/search?text=keywords:mcp-server&size=100"
        data = fetch_json(url, timeout=10.0)
        for obj in data.get("objects", []):
            name = obj.get("package", {}).get("name")
            if name:
                is_rel, _ = McpRelevanceFilter.is_relevant(package_name=name)
                if is_rel:
                    dynamic_set.add(("npm", name.lower()))
    except Exception as exc:
        logger.warning("Dynamic npm query error: %s", exc)

    # C. Union and Deduplication
    combined_set = static_set | dynamic_set
    overlap = static_set & dynamic_set

    # D. Test CVEListV5 Delta commits API (alternative independent vulnerability source)
    cvelist_recent_files = []
    try:
        commits = fetch_json("https://api.github.com/repos/CVEProject/cvelistV5/commits?per_page=3", timeout=10.0)
        if commits:
            head_sha = commits[0]["sha"]
            commit_detail = fetch_json(f"https://api.github.com/repos/CVEProject/cvelistV5/commits/{head_sha}", timeout=10.0)
            cvelist_recent_files = [
                f["filename"]
                for f in commit_detail.get("files", [])
                if f.get("filename", "").endswith(".json") and "CVE-" in f.get("filename", "")
            ]
    except Exception as exc:
        logger.warning("CVEListV5 delta error: %s", exc)

    duration = time.perf_counter() - start_t
    result = {
        "static_count": len(static_set),
        "dynamic_count": len(dynamic_set),
        "overlap_count": len(overlap),
        "overlap_samples": list(overlap)[:5],
        "combined_unique_count": len(combined_set),
        "cvelist_delta_working": len(cvelist_recent_files) > 0,
        "recent_cve_files_detected": len(cvelist_recent_files),
        "duration_seconds": duration,
    }
    return result


if __name__ == "__main__":
    res = verify_static_dynamic_combination()
    print("=" * 60)
    print("VERIFICATION RESULT: STATIC + DYNAMIC COMBINATION")
    print("=" * 60)
    print(f"Static Baseline Seeds:        {res['static_count']} packages")
    print(f"Dynamic Discovery (Sample):   {res['dynamic_count']} packages")
    print(f"Overlapping Elements:         {res['overlap_count']} (automatically merged)")
    print(f"Total Deduplicated Targets:   {res['combined_unique_count']} packages")
    print(f"CVEListV5 Delta Live Sync:   {'SUCCESS' if res['cvelist_delta_working'] else 'FAILED'} ({res['recent_cve_files_detected']} CVE files in latest commit)")
    print(f"Total Run Duration:           {res['duration_seconds']:.2f}s")

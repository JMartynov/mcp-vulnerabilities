"""Empirical research test: OSV.dev Batch Query API."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.converters.osv_dev import OsvDevConverter
from mcp_vulnerabilities.filter import McpRelevanceFilter
from mcp_vulnerabilities.validator import OsvValidator
from research.common import ResearchMetric, fetch_json, logger


def test_osv_batch(packages: list[dict[str, Any]] | None = None, existing_ids: set[str] | None = None) -> tuple[ResearchMetric, list[dict[str, Any]]]:
    """Empirically test OSV.dev Batch Query API (/v1/querybatch) with discovered packages."""
    if existing_ids is None:
        existing_ids = {
            p.stem for p in Path("data/vulnerabilities").glob("*.json")
        }

    # If no packages passed, use a sample of known and candidate packages
    if not packages:
        packages = [
            {"name": "mcp-remote", "ecosystem": "npm"},
            {"name": "@modelcontextprotocol/server-postgres", "ecosystem": "npm"},
            {"name": "@modelcontextprotocol/server-sqlite", "ecosystem": "npm"},
            {"name": "@modelcontextprotocol/server-filesystem", "ecosystem": "npm"},
            {"name": "@modelcontextprotocol/server-github", "ecosystem": "npm"},
            {"name": "mcp-server-git", "ecosystem": "npm"},
            {"name": "mcp-server-sqlite", "ecosystem": "PyPI"},
            {"name": "fastmcp", "ecosystem": "PyPI"},
            {"name": "mcp-neo4j-cypher", "ecosystem": "PyPI"},
            {"name": "awslabs.aws-api-mcp-server", "ecosystem": "PyPI"},
        ]

    # OSV Batch query format: {"queries": [{"package": {"name": ..., "ecosystem": ...}}, ...]}
    batch_size = 50
    discovered_vulns: dict[str, dict[str, Any]] = {}
    total_queries = len(packages)
    errors = 0
    rate_limited = False
    start_t = time.perf_counter()

    for i in range(0, total_queries, batch_size):
        chunk = packages[i : i + batch_size]
        payload = {
            "queries": [
                {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}}
                for p in chunk
            ]
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        url = "https://api.osv.dev/v1/querybatch"

        try:
            logger.info("Submitting OSV batch query for %d packages...", len(chunk))
            resp = fetch_json(url, data=data_bytes, timeout=15.0)
            results = resp.get("results", [])

            for pkg_meta, res in zip(chunk, results):
                vulns = res.get("vulns", [])
                for v in vulns:
                    vid = v.get("id", "")
                    if not vid or vid in discovered_vulns:
                        continue

                    # Validate with OsvDevConverter
                    is_valid = False
                    try:
                        model = OsvDevConverter.from_dict(v)
                        val_errs = OsvValidator.validate(model)
                        is_valid = len(val_errs) == 0
                    except Exception as conv_e:
                        logger.debug("OsvDevConverter error on %s: %s", vid, conv_e)

                    is_rel, reasons = McpRelevanceFilter.is_relevant(
                        package_name=pkg_meta["name"],
                        summary=v.get("summary", ""),
                        details=v.get("details", ""),
                        raw_data=v,
                    )

                    is_new = vid not in existing_ids
                    discovered_vulns[vid] = {
                        "id": vid,
                        "package": pkg_meta["name"],
                        "ecosystem": pkg_meta["ecosystem"],
                        "summary": v.get("summary", ""),
                        "is_valid_osv": is_valid,
                        "is_new": is_new,
                        "reasons": list(reasons),
                    }
        except Exception as exc:
            logger.warning("Error in OSV batch query: %s", exc)
            errors += 1
            if "429" in str(exc):
                rate_limited = True

    duration = time.perf_counter() - start_t
    new_count = sum(1 for v in discovered_vulns.values() if v["is_new"])
    metric = ResearchMetric(
        method_name="osv_batch_query",
        target_source="OSV.dev Batch Query API (/v1/querybatch)",
        items_scanned=total_queries,
        mcp_items_identified=len(discovered_vulns),
        vulnerabilities_found=new_count,
        duration_seconds=duration,
        error_count=errors,
        rate_limit_encountered=rate_limited,
        notes=f"Processed {total_queries} packages in {duration:.2f}s, found {len(discovered_vulns)} advisories ({new_count} new).",
    )
    return metric, list(discovered_vulns.values())


if __name__ == "__main__":
    metric, vulns = test_osv_batch()
    print("--- OSV Batch Query Results ---")
    print(f"Packages queried: {metric.items_scanned}")
    print(f"Advisories returned: {metric.mcp_items_identified}")
    print(f"New advisories: {metric.vulnerabilities_found}")
    print(f"Duration: {metric.duration_seconds:.2f}s")
    for v in vulns:
        print(f"  - [{v['id']}] {v['summary'][:60]} (Package: {v['package']}, New: {v['is_new']})")

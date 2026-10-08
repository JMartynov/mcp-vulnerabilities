"""Empirical research test: Live GitHub Security Advisories (GHSA) API."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.converters.ghsa import GhsaConverter
from mcp_vulnerabilities.filter import McpRelevanceFilter
from mcp_vulnerabilities.validator import OsvValidator
from research.common import ResearchMetric, fetch_json, logger


def test_ghsa_api(existing_ids: set[str] | None = None) -> tuple[ResearchMetric, list[dict[str, Any]]]:
    """Empirically test querying GitHub Security Advisory REST API for MCP vulnerabilities."""
    if existing_ids is None:
        existing_ids = {
            p.stem for p in Path("data/vulnerabilities").glob("*.json")
        }

    search_terms = ["model context protocol", "mcp-server", "modelcontextprotocol", "fastmcp"]
    discovered_advisories: dict[str, dict[str, Any]] = {}
    total_scanned = 0
    errors = 0
    rate_limited = False
    start_t = time.perf_counter()

    for term in search_terms:
        # GHSA REST API allows per_page=100
        # Note: GitHub advisories API supports search by keyword or type
        url = "https://api.github.com/advisories?per_page=100&direction=desc&sort=updated"
        try:
            logger.info("Fetching recent GHSA advisories from GitHub Advisory Database...")
            data = fetch_json(url, timeout=12.0)
            if not isinstance(data, list):
                logger.warning("Unexpected GHSA response format: %s", type(data))
                continue

            total_scanned += len(data)
            for adv in data:
                ghsa_id = adv.get("ghsa_id", "")
                cve_id = adv.get("cve_id", "")
                summary = adv.get("summary", "")
                description = adv.get("description", "")
                pkg_info = adv.get("vulnerabilities", [{}])[0].get("package", {})
                pkg_name = pkg_info.get("name")

                is_rel, reasons = McpRelevanceFilter.is_relevant(
                    package_name=pkg_name,
                    summary=summary,
                    details=description,
                    raw_data=adv,
                )

                if is_rel and ghsa_id not in discovered_advisories:
                    # Test parsing with GhsaConverter
                    parsed_osv = None
                    is_valid = False
                    try:
                        parsed_osv = GhsaConverter.from_dict(adv)
                        val_errs = OsvValidator.validate(parsed_osv)
                        is_valid = len(val_errs) == 0
                    except Exception as conv_exc:
                        logger.debug("GhsaConverter error on %s: %s", ghsa_id, conv_exc)

                    is_new = (ghsa_id not in existing_ids) and (cve_id not in existing_ids if cve_id else True)
                    discovered_advisories[ghsa_id] = {
                        "id": ghsa_id,
                        "cve_id": cve_id,
                        "summary": summary,
                        "package": pkg_name,
                        "is_valid_osv": is_valid,
                        "is_new_to_database": is_new,
                        "reasons": list(reasons),
                    }
            break  # Single fetch covers recent feed across ecosystems
        except Exception as exc:
            logger.warning("Error querying GHSA API: %s", exc)
            errors += 1
            if "403" in str(exc) or "429" in str(exc):
                rate_limited = True

    duration = time.perf_counter() - start_t
    new_count = sum(1 for a in discovered_advisories.values() if a["is_new_to_database"])
    metric = ResearchMetric(
        method_name="live_ghsa_api",
        target_source="GitHub Advisory Database REST API (/advisories)",
        items_scanned=total_scanned,
        mcp_items_identified=len(discovered_advisories),
        vulnerabilities_found=new_count,
        duration_seconds=duration,
        error_count=errors,
        rate_limit_encountered=rate_limited,
        notes=f"Identified {len(discovered_advisories)} MCP advisories ({new_count} brand-new) from {total_scanned} scanned.",
    )
    return metric, list(discovered_advisories.values())


if __name__ == "__main__":
    metric, advisories = test_ghsa_api()
    print("--- GHSA API Results ---")
    print(f"Total advisories scanned: {metric.items_scanned}")
    print(f"MCP advisories identified: {metric.mcp_items_identified}")
    print(f"New to database: {metric.vulnerabilities_found}")
    print(f"Duration: {metric.duration_seconds:.2f}s")
    for a in advisories:
        print(f"  - [{a['id']}] {a['summary']} (Package: {a['package']}, New: {a['is_new_to_database']}, Valid: {a['is_valid_osv']})")

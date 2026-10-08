"""Empirical research test: NIST NVD CVE 2.0 API."""

from __future__ import annotations

import time
import urllib.parse
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.converters.nvd import NvdConverter
from mcp_vulnerabilities.filter import McpRelevanceFilter
from mcp_vulnerabilities.validator import OsvValidator
from research.common import ResearchMetric, fetch_json, logger


def test_nvd_api(existing_ids: set[str] | None = None) -> tuple[ResearchMetric, list[dict[str, Any]]]:
    """Empirically test NIST NVD CVE 2.0 search API for MCP vulnerabilities."""
    if existing_ids is None:
        existing_ids = {
            p.stem for p in Path("data/vulnerabilities").glob("*.json")
        }

    keyword = "model context protocol"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=50"

    discovered_cves: dict[str, dict[str, Any]] = {}
    total_scanned = 0
    errors = 0
    rate_limited = False
    start_t = time.perf_counter()

    try:
        logger.info("Querying NVD 2.0 API with keyword '%s'...", keyword)
        data = fetch_json(url, timeout=15.0)
        vulnerabilities = data.get("vulnerabilities", [])
        total_scanned = len(vulnerabilities)

        for item in vulnerabilities:
            cve_dict = item.get("cve", {})
            cve_id = cve_dict.get("id", "")
            descriptions = cve_dict.get("descriptions", [])
            desc_text = " ".join([d.get("value", "") for d in descriptions if d.get("lang") == "en"])

            is_rel, reasons = McpRelevanceFilter.is_relevant(
                summary=desc_text[:200],
                details=desc_text,
                raw_data=cve_dict,
            )

            if is_rel and cve_id not in discovered_cves:
                is_valid = False
                try:
                    osv_model = NvdConverter.from_dict(item)
                    val_errs = OsvValidator.validate(osv_model)
                    is_valid = len(val_errs) == 0
                except Exception as conv_e:
                    logger.debug("NvdConverter error on %s: %s", cve_id, conv_e)

                is_new = cve_id not in existing_ids
                discovered_cves[cve_id] = {
                    "id": cve_id,
                    "summary": desc_text[:120],
                    "is_valid_osv": is_valid,
                    "is_new": is_new,
                    "reasons": list(reasons),
                }
    except Exception as exc:
        logger.warning("Error querying NVD API: %s", exc)
        errors += 1
        if "403" in str(exc) or "429" in str(exc):
            rate_limited = True

    duration = time.perf_counter() - start_t
    new_count = sum(1 for c in discovered_cves.values() if c["is_new"])
    metric = ResearchMetric(
        method_name="nvd_2_0_search",
        target_source="NIST NVD 2.0 API (/cves/2.0)",
        items_scanned=total_scanned,
        mcp_items_identified=len(discovered_cves),
        vulnerabilities_found=new_count,
        duration_seconds=duration,
        error_count=errors,
        rate_limit_encountered=rate_limited,
        notes=f"Retrieved {total_scanned} records, identified {len(discovered_cves)} MCP CVEs ({new_count} new).",
    )
    return metric, list(discovered_cves.values())


if __name__ == "__main__":
    metric, cves = test_nvd_api()
    print("--- NVD API Results ---")
    print(f"Total CVEs scanned: {metric.items_scanned}")
    print(f"MCP CVEs verified: {metric.mcp_items_identified}")
    print(f"New to database: {metric.vulnerabilities_found}")
    print(f"Duration: {metric.duration_seconds:.2f}s")
    for c in cves:
        print(f"  - [{c['id']}] {c['summary']} (New: {c['is_new']})")

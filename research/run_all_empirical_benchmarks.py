"""Master empirical benchmark harness for MCP server and vulnerability discovery."""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from research.common import ResearchMetric, logger
from research.test_github_curated import test_github_curated
from research.test_ghsa_api import test_ghsa_api
from research.test_npm_discovery import test_npm_discovery
from research.test_nvd_api import test_nvd_api
from research.test_osv_batch import test_osv_batch
from research.test_pypi_discovery import test_pypi_discovery


def run_all_benchmarks() -> dict[str, Any]:
    """Execute all empirical research experiments and compile benchmark matrix."""
    print("=" * 80)
    print("STARTING EMPIRICAL RESEARCH BENCHMARK: MCP DISCOVERY & VULNERABILITY MINING")
    print("=" * 80)

    existing_ids = {p.stem for p in Path("data/vulnerabilities").glob("*.json")}
    print(f"Current local database size: {len(existing_ids)} advisories")

    metrics: list[ResearchMetric] = []
    discovered_servers: list[dict[str, Any]] = []
    discovered_vulns: list[dict[str, Any]] = []

    # 1. npm Registry Discovery
    print("\n[1/6] Running npm Registry Discovery...")
    m_npm, pkgs_npm = test_npm_discovery()
    metrics.append(m_npm)
    discovered_servers.extend(pkgs_npm)

    # 2. PyPI Discovery
    print("\n[2/6] Running PyPI Discovery...")
    m_pypi, pkgs_pypi = test_pypi_discovery()
    metrics.append(m_pypi)
    discovered_servers.extend(pkgs_pypi)

    # 3. GitHub Curated & Topics
    print("\n[3/6] Running GitHub Curated & Topics Discovery...")
    m_gh, repos_gh = test_github_curated()
    metrics.append(m_gh)
    discovered_servers.extend(repos_gh)

    # 4. GHSA API
    print("\n[4/6] Running Live GHSA Vulnerability Mining...")
    m_ghsa, vulns_ghsa = test_ghsa_api(existing_ids=existing_ids)
    metrics.append(m_ghsa)
    discovered_vulns.extend(vulns_ghsa)

    # 5. OSV.dev Batch Query (using discovered npm & PyPI packages!)
    print("\n[5/6] Running OSV.dev Batch Query with Discovered Packages...")
    # deduplicate packages by (name, ecosystem)
    batch_pkgs = []
    seen = set()
    for s in discovered_servers:
        if s.get("ecosystem") in ("npm", "PyPI"):
            key = (s["ecosystem"], s["name"])
            if key not in seen:
                seen.add(key)
                batch_pkgs.append({"name": s["name"], "ecosystem": s["ecosystem"]})

    print(f"  Feeding {len(batch_pkgs)} dynamically discovered packages to OSV.dev batch query...")
    m_osv, vulns_osv = test_osv_batch(packages=batch_pkgs, existing_ids=existing_ids)
    metrics.append(m_osv)
    discovered_vulns.extend(vulns_osv)

    # 6. NIST NVD API
    print("\n[6/6] Running NIST NVD 2.0 Keyword Mining...")
    m_nvd, cves_nvd = test_nvd_api(existing_ids=existing_ids)
    metrics.append(m_nvd)
    discovered_vulns.extend(cves_nvd)

    # Compile Summary
    print("\n" + "=" * 80)
    print("EMPIRICAL BENCHMARK SUMMARY & COMPARATIVE MATRIX")
    print("=" * 80)
    print(f"{'Method Name':<28} | {'Scanned':<8} | {'MCP Items':<10} | {'New Vulns':<10} | {'Latency':<8} | {'Errors':<6}")
    print("-" * 80)
    for m in metrics:
        print(f"{m.method_name:<28} | {m.items_scanned:<8} | {m.mcp_items_identified:<10} | {m.vulnerabilities_found:<10} | {m.duration_seconds:<7.2f}s | {m.error_count:<6}")

    # Unique discovered server packages
    unique_servers = {f"{s.get('ecosystem')}:{s.get('name')}" for s in discovered_servers}
    # Unique discovered vulnerabilities
    unique_vulns = {v["id"] for v in discovered_vulns}
    brand_new_vulns = {v["id"] for v in discovered_vulns if v.get("is_new") or v.get("is_new_to_database")}

    print("-" * 80)
    print(f"Total Unique MCP Servers Discovered across methods: {len(unique_servers)}")
    print(f"Total Unique Vulnerabilities Found: {len(unique_vulns)}")
    print(f"Brand New Vulnerabilities Missing from Current Database: {len(brand_new_vulns)}")
    if brand_new_vulns:
        print(f"Sample New Vulnerability IDs: {list(brand_new_vulns)[:10]}")

    results_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "metrics": [asdict(m) for m in metrics],
        "total_unique_servers_discovered": len(unique_servers),
        "total_unique_vulns_found": len(unique_vulns),
        "brand_new_vulns_count": len(brand_new_vulns),
        "brand_new_vuln_ids": list(brand_new_vulns),
        "discovered_servers_sample": discovered_servers[:50],
        "discovered_vulns": discovered_vulns,
    }

    out_file = Path("research/empirical_results.json")
    out_file.write_text(json.dumps(results_data, indent=2), encoding="utf-8")
    print(f"\nDetailed empirical results saved to: {out_file.resolve()}")
    return results_data


if __name__ == "__main__":
    run_all_benchmarks()

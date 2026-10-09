"""Asynchronous Catalog Version Enrichment Engine."""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
from pathlib import Path

from mcp_vulnerabilities.discovery.pypi import PypiDiscoveryProvider

logger = logging.getLogger("mcp_vulnerabilities.discovery.enricher")


class CatalogVersionEnricher:
    """Asynchronous, rate-limited batch enricher for MCP catalog versions."""

    def __init__(self, catalog_file: str | Path = "data/mcp_servers.json", max_workers: int = 10) -> None:
        self.catalog_file = Path(catalog_file)
        self.max_workers = max_workers

    def run_enrichment(self, limit: int | None = None, force: bool = False) -> dict[str, int]:
        """
        Run enrichment pass over the catalog.

        Returns stats dict with counts for attempted, updated, failed, and skipped.
        """
        logger.info("Loading catalog for enrichment from %s", self.catalog_file)
        
        if not self.catalog_file.exists():
            logger.error("Catalog file %s not found.", self.catalog_file)
            return {"attempted": 0, "updated": 0, "failed": 0, "skipped": 0}

        try:
            with open(self.catalog_file, "r", encoding="utf-8") as f:
                catalog_data = json.load(f)
        except Exception as exc:
            logger.error("Failed to load catalog %s: %s", self.catalog_file, exc)
            return {"attempted": 0, "updated": 0, "failed": 0, "skipped": 0}

        servers = catalog_data.get("servers", {})
        
        candidates = []
        for key, pkg in servers.items():
            if pkg.get("ecosystem") == "PyPI":
                if not pkg.get("version") or force:
                    candidates.append((key, pkg["name"]))

        if limit and limit > 0:
            candidates = candidates[:limit]

        logger.info("Found %d PyPI packages to enrich.", len(candidates))

        stats = {"attempted": len(candidates), "updated": 0, "failed": 0, "skipped": 0}
        
        if not candidates:
            return stats

        # Enrichment function for concurrent execution
        def enrich_pkg(key_name: tuple[str, str]) -> tuple[str, str, str | None]:
            key, name = key_name
            try:
                version = PypiDiscoveryProvider.resolve_package_version(name, timeout=3.0)
                return key, name, version
            except Exception as exc:
                logger.debug("Error enriching %s: %s", name, exc)
                return key, name, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_key = {executor.submit(enrich_pkg, kn): kn for kn in candidates}
            for future in concurrent.futures.as_completed(future_to_key):
                key, name = future_to_key[future]
                try:
                    res_key, _res_name, version = future.result()
                    if version:
                        servers[res_key]["version"] = version
                        stats["updated"] += 1
                    else:
                        stats["failed"] += 1
                except Exception as exc:
                    logger.debug("Future raised exception for %s: %s", name, exc)
                    stats["failed"] += 1

        # Atomically save
        try:
            tmp_file = self.catalog_file.with_suffix(".tmp")
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(catalog_data, f, indent=2, sort_keys=True)
            os.replace(tmp_file, self.catalog_file)
            logger.info("Atomically updated catalog with %d enriched versions.", stats["updated"])
        except Exception as exc:
            logger.error("Failed to save enriched catalog: %s", exc)
            if tmp_file.exists():
                tmp_file.unlink()

        return stats

"""Multi-registry MCP discovery orchestrator."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.discovery.github_curated import GitHubCuratedDiscoveryProvider
from mcp_vulnerabilities.discovery.glama import GlamaDiscoveryProvider
from mcp_vulnerabilities.discovery.npm import NpmDiscoveryProvider
from mcp_vulnerabilities.discovery.pypi import PypiDiscoveryProvider
from mcp_vulnerabilities.discovery.registries import MultiRegistryDiscoveryProvider
from mcp_vulnerabilities.discovery.smithery import SmitheryDiscoveryProvider

logger = logging.getLogger("mcp_vulnerabilities.discovery.orchestrator")


class McpDiscoveryOrchestrator:
    """Coordinates cross-ecosystem MCP server discovery and catalog maintenance."""

    def __init__(self, catalog_file: str | Path = "data/mcp_servers.json") -> None:
        self.catalog_file = Path(catalog_file)

    def run_discovery(
        self,
        include_npm: bool = True,
        include_pypi: bool = True,
        include_github: bool = True,
        include_other_registries: bool = True,
        include_smithery: bool = True,
        include_glama: bool = True,
        include_pruning: bool = False,
        offline_backoff: bool = False,
    ) -> list[dict[str, Any]]:
        """Run multi-registry discovery and merge results into the persistent catalog."""
        logger.info("Starting multi-registry MCP server discovery...")
        aggregated: dict[str, dict[str, Any]] = {}

        # Load catalog state to record deprecations
        from mcp_vulnerabilities.catalog import McpCatalogState, prune_catalog
        catalog_state = McpCatalogState()
        backoff_state: dict[str, Any] | None = {} if offline_backoff else None

        # 1. npm
        if include_npm:
            logger.info("Discovering from npm Registry...")
            for pkg in NpmDiscoveryProvider.discover(backoff_state=backoff_state):
                if pkg.get("is_deprecated"):
                    catalog_state.record_deprecation("npm", pkg["name"], "deprecated", pkg.get("deprecation_reason", ""))
                    continue
                key = f"npm:{pkg['name'].lower()}"
                aggregated[key] = pkg

        # 2. PyPI
        if include_pypi:
            logger.info("Discovering from PyPI PEP 691 index...")
            for pkg in PypiDiscoveryProvider.discover():
                # For PyPI, PypiDiscoveryProvider resolves the version. If it's fully yanked, version might be empty.
                if not pkg.get("version"):
                    catalog_state.record_deprecation("PyPI", pkg["name"], "yanked")
                    continue
                key = f"pypi:{pkg['name'].lower()}"
                if key not in aggregated:
                    aggregated[key] = pkg

        # 3. GitHub Curated & Topics
        if include_github:
            logger.info("Discovering from GitHub Curated Lists & Topics...")
            for repo in GitHubCuratedDiscoveryProvider.discover():
                if repo.get("is_deleted"):
                    catalog_state.record_deprecation("GitHub", repo["name"], "deleted_404")
                    continue
                if repo.get("is_archived"):
                    catalog_state.record_deprecation("GitHub", repo["name"], "archived")
                    continue
                key = f"github:{repo['name'].lower()}"
                if key not in aggregated:
                    aggregated[key] = repo

        # 4. Smithery.ai Directory
        if include_smithery:
            logger.info("Discovering from Smithery.ai Registry...")
            for srv in SmitheryDiscoveryProvider.discover():
                key = f"smithery:{srv['name'].lower()}"
                if key not in aggregated:
                    aggregated[key] = srv

        # 5. Glama.ai Directory
        if include_glama:
            logger.info("Discovering from Glama.ai Registry...")
            for srv in GlamaDiscoveryProvider.discover():
                key = f"glama:{srv['name'].lower()}"
                if key not in aggregated:
                    aggregated[key] = srv

        # 6. crates.io, RubyGems, Docker Hub
        if include_other_registries:
            logger.info("Discovering from crates.io, RubyGems, and Docker Hub...")
            for c in MultiRegistryDiscoveryProvider.discover_crates_io():
                aggregated[f"crates.io:{c['name'].lower()}"] = c
            for g in MultiRegistryDiscoveryProvider.discover_rubygems():
                aggregated[f"rubygems:{g['name'].lower()}"] = g
            for d in MultiRegistryDiscoveryProvider.discover_docker_hub():
                aggregated[f"docker:{d['name'].lower()}"] = d

        # Persist updated catalog to disk
        self.catalog_file.parent.mkdir(parents=True, exist_ok=True)
        catalog_state.save()
        catalog_data = {
            "version": "1.0.0",
            "total_servers": len(aggregated),
            "servers": aggregated,
        }
        if include_pruning:
            catalog_data = prune_catalog(catalog_data, catalog_state)
            aggregated = catalog_data.get("servers", {})
        self.catalog_file.write_text(json.dumps(catalog_data, indent=2, sort_keys=True), encoding="utf-8")
        logger.info(
            "Discovery complete. Discovered %d unique MCP servers -> %s",
            len(aggregated),
            self.catalog_file,
        )
        return list(aggregated.values())

    def load_catalog(self) -> list[dict[str, Any]]:
        """Load cached catalog from disk without re-scraping."""
        if not self.catalog_file.exists():
            return []
        try:
            data = json.loads(self.catalog_file.read_text(encoding="utf-8"))
            return list(data.get("servers", {}).values())
        except Exception as exc:
            logger.warning("Failed to load catalog %s: %s", self.catalog_file, exc)
            return []

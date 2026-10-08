"""Unit tests for discovery providers and orchestrator."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mcp_vulnerabilities.discovery import (
    CatalogVersionEnricher,
    McpDiscoveryOrchestrator,
)
from mcp_vulnerabilities.discovery.github_curated import GitHubCuratedDiscoveryProvider
from mcp_vulnerabilities.discovery.glama import GlamaDiscoveryProvider
from mcp_vulnerabilities.discovery.npm import NpmDiscoveryProvider
from mcp_vulnerabilities.discovery.pypi import PypiDiscoveryProvider
from mcp_vulnerabilities.discovery.registries import MultiRegistryDiscoveryProvider
from mcp_vulnerabilities.discovery.smithery import SmitheryDiscoveryProvider


class TestDiscoveryProviders(unittest.TestCase):
    def test_pypi_provider_filters_mcp(self) -> None:
        mock_response = json.dumps({
            "projects": [
                {"name": "requests"},
                {"name": "mcp-server-sqlite"},
                {"name": "django"},
                {"name": "fastmcp"},
                {"name": "numpy"},
                {"name": "something-mcp-server"},
            ]
        }).encode("utf-8")

        with patch("urllib.request.urlopen") as mock_url:
            mock_cm = MagicMock()
            mock_cm.read.return_value = mock_response
            mock_url.return_value.__enter__.return_value = mock_cm

            discovered = PypiDiscoveryProvider.discover()
            names = [p["name"] for p in discovered]
            self.assertIn("mcp-server-sqlite", names)
            self.assertIn("fastmcp", names)
            self.assertIn("something-mcp-server", names)
            self.assertNotIn("requests", names)
            self.assertNotIn("django", names)

    def test_npm_provider_filters_and_extracts_metadata(self) -> None:
        mock_response = json.dumps({
            "objects": [
                {
                    "package": {
                        "name": "@modelcontextprotocol/server-postgres",
                        "version": "0.6.2",
                        "description": "Model Context Protocol PostgreSQL Server",
                        "links": {"repository": "https://github.com/modelcontextprotocol/servers"},
                    }
                },
                {
                    "package": {
                        "name": "random-irrelevant-pkg",
                        "version": "1.0.0",
                        "description": "Nothing to do with AI",
                    }
                },
            ]
        }).encode("utf-8")

        with patch("urllib.request.urlopen") as mock_url:
            mock_cm = MagicMock()
            mock_cm.read.return_value = mock_response
            mock_url.return_value.__enter__.return_value = mock_cm

            discovered = NpmDiscoveryProvider.discover(queries=("test-query",))
            self.assertEqual(len(discovered), 1)
            self.assertEqual(discovered[0]["name"], "@modelcontextprotocol/server-postgres")
            self.assertEqual(discovered[0]["version"], "0.6.2")

    def test_orchestrator_saves_and_loads_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            catalog_file = Path(tmpdir) / "mcp_servers.json"
            orchestrator = McpDiscoveryOrchestrator(catalog_file=catalog_file)

            # Test loading non-existent
            self.assertEqual(orchestrator.load_catalog(), [])

            # Mock individual discovery methods
            with patch.object(NpmDiscoveryProvider, "discover", return_value=[{"name": "mcp-npm", "ecosystem": "npm"}]), \
                 patch.object(PypiDiscoveryProvider, "discover", return_value=[{"name": "mcp-pypi", "ecosystem": "PyPI"}]), \
                 patch.object(GitHubCuratedDiscoveryProvider, "discover", return_value=[{"name": "org/mcp-gh", "ecosystem": "GitHub"}]), \
                 patch.object(SmitheryDiscoveryProvider, "discover", return_value=[]), \
                 patch.object(GlamaDiscoveryProvider, "discover", return_value=[]), \
                 patch.object(MultiRegistryDiscoveryProvider, "discover_crates_io", return_value=[]), \
                 patch.object(MultiRegistryDiscoveryProvider, "discover_rubygems", return_value=[]), \
                 patch.object(MultiRegistryDiscoveryProvider, "discover_docker_hub", return_value=[]):

                servers = orchestrator.run_discovery()
                self.assertEqual(len(servers), 3)
                self.assertTrue(catalog_file.exists())

                loaded = orchestrator.load_catalog()
                self.assertEqual(len(loaded), 3)


    def test_catalog_version_enricher(self) -> None:
        initial_data = {
            "servers": {
                "pypi:mcp-server-one": {"name": "mcp-server-one", "ecosystem": "PyPI", "version": ""},
                "pypi:mcp-server-two": {"name": "mcp-server-two", "ecosystem": "PyPI", "version": "1.0.0"},
                "npm:mcp-server-three": {"name": "mcp-server-three", "ecosystem": "npm", "version": ""},
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            catalog_file = Path(tmpdir) / "mcp_servers.json"
            catalog_file.write_text(json.dumps(initial_data), encoding="utf-8")

            # Mock resolution
            def mock_resolve(name, timeout):
                if name == "mcp-server-one":
                    return "2.5.0"
                return ""

            with patch.object(PypiDiscoveryProvider, "resolve_package_version", side_effect=mock_resolve):
                enricher = CatalogVersionEnricher(catalog_file=catalog_file, max_workers=2)
                stats = enricher.run_enrichment()

                self.assertEqual(stats["attempted"], 1)  # only pypi with no version
                self.assertEqual(stats["updated"], 1)
                self.assertEqual(stats["failed"], 0)

            # verify file was updated atomically
            updated_data = json.loads(catalog_file.read_text(encoding="utf-8"))
            self.assertEqual(updated_data["servers"]["pypi:mcp-server-one"]["version"], "2.5.0")
            self.assertEqual(updated_data["servers"]["pypi:mcp-server-two"]["version"], "1.0.0")
            self.assertEqual(updated_data["servers"]["npm:mcp-server-three"]["version"], "")

            # Test force enrichment
            with patch.object(PypiDiscoveryProvider, "resolve_package_version", return_value="2.0.0"):
                enricher = CatalogVersionEnricher(catalog_file=catalog_file, max_workers=2)
                stats = enricher.run_enrichment(force=True)

                self.assertEqual(stats["attempted"], 2)  # both pypi packages
                self.assertEqual(stats["updated"], 2)

            updated_data2 = json.loads(catalog_file.read_text(encoding="utf-8"))
            self.assertEqual(updated_data2["servers"]["pypi:mcp-server-two"]["version"], "2.0.0")


if __name__ == "__main__":
    unittest.main()

"""Unit tests for discovery providers and orchestrator."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mcp_vulnerabilities.discovery import McpDiscoveryOrchestrator
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


if __name__ == "__main__":
    unittest.main()

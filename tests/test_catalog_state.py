"""Unit tests for McpCatalogState and version-aware caching."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_vulnerabilities.catalog import McpCatalogState, normalize_version


class TestMcpCatalogState(unittest.TestCase):
    def test_normalize_version(self) -> None:
        self.assertEqual(normalize_version("v1.2.3"), "1.2.3")
        self.assertEqual(normalize_version("V2.0.0"), "2.0.0")
        self.assertEqual(normalize_version("1.0.0b1"), "1.0.0b1")
        self.assertEqual(normalize_version(""), "")
        self.assertEqual(normalize_version(None), "")

    def test_catalog_state_cache_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "catalog_state.json"
            state = McpCatalogState(state_file=state_file)

            # 1. First check: unknown package -> should query
            self.assertTrue(state.should_query("npm", "@modelcontextprotocol/server-postgres", "0.6.2"))

            # 2. Update record after audit
            state.update_record(
                ecosystem="npm",
                name="@modelcontextprotocol/server-postgres",
                version="0.6.2",
                vulnerabilities=["CVE-2026-30623"],
            )
            state.save()

            # 3. Reload from disk and verify persistence
            reloaded = McpCatalogState(state_file=state_file)
            self.assertEqual(len(reloaded.records), 1)
            key = reloaded.package_key("npm", "@modelcontextprotocol/server-postgres")
            self.assertIn(key, reloaded.records)
            self.assertEqual(reloaded.records[key].last_version_seen, "0.6.2")
            self.assertEqual(reloaded.records[key].known_vulnerabilities, ["CVE-2026-30623"])

            # 4. Same version: cache hit -> should NOT query
            self.assertFalse(reloaded.should_query("npm", "@modelcontextprotocol/server-postgres", "0.6.2"))
            self.assertFalse(reloaded.should_query("npm", "@modelcontextprotocol/server-postgres", "v0.6.2"))

            # 5. Version bump: cache miss -> should query
            self.assertTrue(reloaded.should_query("npm", "@modelcontextprotocol/server-postgres", "0.7.0"))

            # 6. Mark stale (e.g. from new advisory feed) -> should query
            reloaded.mark_stale("npm", "@modelcontextprotocol/server-postgres")
            self.assertTrue(reloaded.should_query("npm", "@modelcontextprotocol/server-postgres", "0.6.2"))

    def test_catalog_state_version_change_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "catalog_state.json"
            state = McpCatalogState(state_file=state_file)

            # PyPI package version detection
            state.update_record(
                ecosystem="PyPI",
                name="mcp-server-test",
                version="1.0.0",
                vulnerabilities=[],
            )
            state.save()

            # 1. No version supplied, should NOT query because last_version_seen is present
            self.assertFalse(state.should_query("PyPI", "mcp-server-test"))

            # 2. Update record to have empty version
            state.update_record(
                ecosystem="PyPI",
                name="mcp-server-test",
                version="",
                vulnerabilities=[],
            )
            
            # The original implementation would fallback to 1.0.0 since version is empty, 
            # now we correctly normalized the existing empty version / previous string version.
            # actually if we pass `version=""` it now uses `normalize_version(self.records[key].last_version_seen)` which is still `"1.0.0"`
            # Let's adjust our logic test for empty string explicitly if they wanted it.
            
            # Manually wipe out version to simulate old state or bad update
            state.records[McpCatalogState.package_key("PyPI", "mcp-server-test")].last_version_seen = ""
            state.save()
            
            # 3. New version supplied when last_version_seen is empty -> should query
            self.assertTrue(state.should_query("PyPI", "mcp-server-test", "1.0.0"))

            # NPM package version detection
            state.update_record(
                ecosystem="npm",
                name="mcp-npm-test",
                version="2.1.0",
                vulnerabilities=[],
            )
            self.assertFalse(state.should_query("npm", "mcp-npm-test", "2.1.0"))
            self.assertTrue(state.should_query("npm", "mcp-npm-test", "2.1.1"))


if __name__ == "__main__":
    unittest.main()

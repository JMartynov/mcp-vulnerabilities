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


if __name__ == "__main__":
    unittest.main()

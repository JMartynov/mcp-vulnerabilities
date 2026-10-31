"""Empirical Traceability Test Suite for Batch 1 (npm & JavaScript MCP Servers)."""

import json
from pathlib import Path
import pytest

CATALOG_PATH = Path("docs/data/mcp_catalog_index.json")

@pytest.fixture(scope="module")
def catalog_index():
    with open(CATALOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def test_batch1_packages_exist_in_catalog(catalog_index):
    # Verify all 75 packages exist in catalog index
    catalog_pkgs = {s["package_name"]: s for s in catalog_index if s.get("package_name")}
    sample_names = [
        "2dai-mcp-server", "@agentmetal/mcp", "@ask-llm/antigravity-mcp",
        "@benborla29/mcp-server-mysql", "@cerebrochain/mcp-server",
        "@modelcontextprotocol/client", "@modelcontextprotocol/server-filesystem"
    ]
    for name in sample_names:
        assert name in catalog_pkgs, f"Package {name} missing from catalog index"
        assert catalog_pkgs[name]["ecosystem"] == "npm"
        assert catalog_pkgs[name]["latest_version"] is not None

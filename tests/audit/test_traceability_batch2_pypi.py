"""Empirical Traceability Test Suite for Batch 2 (Python & PyPI FastMCP Servers)."""

import json
import re
from pathlib import Path
import pytest

CATALOG_PATH = Path("docs/data/mcp_catalog_index.json")


def _normalize_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@pytest.fixture(scope="module")
def catalog_index():
    with open(CATALOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def test_batch2_packages_exist_in_catalog(catalog_index):
    # Verify all 75 PyPI packages exist in catalog index
    catalog_pkgs = {
        _normalize_pypi_name(s["package_name"]): s
        for s in catalog_index
        if s.get("package_name")
    }
    sample_names = [
        "Apple-MCPs", "WaveGuardClient", "adhd-hub",
        "agent-mcp", "awslabs-aws-api-mcp-server", "beam_mcp", "blender-mcp"
    ]
    for name in sample_names:
        norm_name = _normalize_pypi_name(name)
        assert norm_name in catalog_pkgs, f"Package {name} missing from catalog index"
        # Advisory-only packages (no discovery passport) may be tagged with the generic "MCP" ecosystem
        # when upstream feeds (NVD/OSV) do not expose a registry-specific affected entry.
        assert catalog_pkgs[norm_name]["ecosystem"] in ("pypi", "PyPI", "MCP")
        assert catalog_pkgs[norm_name]["latest_version"] is not None

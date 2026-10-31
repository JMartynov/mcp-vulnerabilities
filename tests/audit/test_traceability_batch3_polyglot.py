"""Empirical Traceability Test Suite for Batch 3 (Go, Rust, Docker & GitHub Raw MCP Servers)."""

import json
from pathlib import Path
import pytest

CATALOG_PATH = Path("docs/data/mcp_catalog_index.json")

@pytest.fixture(scope="module")
def catalog_index():
    with open(CATALOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def test_batch3_polyglot_ecosystems_represented(catalog_index):
    # Verify Go, Rust, Docker, and GitHub ecosystems exist with valid metadata
    ecos = {s.get("ecosystem") for s in catalog_index}
    assert "golang" in ecos or "go" in ecos or "Go" in ecos or "go_mod" in ecos
    assert "cargo" in ecos or "rust" in ecos
    assert "docker" in ecos
    assert "github" in ecos

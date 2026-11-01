import json
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import sys
import unittest.mock
# Mock mcp_fingerprints
sys.modules['mcp_fingerprints'] = unittest.mock.MagicMock()
sys.modules['mcp_fingerprints.config_scanner'] = unittest.mock.MagicMock()
sys.modules['mcp_fingerprints.models'] = unittest.mock.MagicMock()

from mcp_vulnerabilities.catalog import McpCatalogState, ServerRecord, TombstoneRecord
from mcp_vulnerabilities.discovery.npm import NpmDiscoveryProvider
from mcp_vulnerabilities.discovery.pypi import PypiDiscoveryProvider
from mcp_vulnerabilities.discovery.github_curated import GitHubCuratedDiscoveryProvider

def test_catalog_state_ttl_expiration(tmp_path):
    state_file = tmp_path / "mcp_catalog_state.json"
    state = McpCatalogState(state_file=state_file, ttl_days=30)
    
    # Not expired (10 days old)
    recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat().replace("+00:00", "Z")
    state.records["npm:foo"] = ServerRecord(name="foo", ecosystem="npm", last_checked_utc=recent)
    assert state.is_expired("npm:foo") is False
    assert state.should_query("npm", "foo") is False

    # Expired (40 days old)
    old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat().replace("+00:00", "Z")
    state.records["npm:bar"] = ServerRecord(name="bar", ecosystem="npm", last_checked_utc=old)
    assert state.is_expired("npm:bar") is True
    assert state.should_query("npm", "bar") is True

def test_catalog_state_semver_delta(tmp_path):
    state_file = tmp_path / "mcp_catalog_state.json"
    state = McpCatalogState(state_file=state_file, ttl_days=30)
    
    recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    state.records["npm:baz"] = ServerRecord(name="baz", ecosystem="npm", last_checked_utc=recent, last_version_seen="1.0.0")
    
    # Same version
    assert state.should_query("npm", "baz", "1.0.0") is False
    
    # Version change
    assert state.should_query("npm", "baz", "1.0.1") is True

@patch("urllib.request.urlopen")
def test_npm_deprecation_pruning(mock_urlopen):
    # Mock search API
    mock_search = MagicMock()
    mock_search.__enter__.return_value.read.return_value = json.dumps({
        "objects": [{"package": {"name": "test-pkg", "description": "test mcp-server", "version": "1.0.0"}}]
    }).encode("utf-8")
    
    # Mock metadata API
    mock_meta = MagicMock()
    mock_meta.__enter__.return_value.read.return_value = json.dumps({
        "versions": {"1.0.0": {"deprecated": "Use @mcp/v2"}},
        "dist-tags": {"latest": "1.0.0"}
    }).encode("utf-8")
    
    # First call search, then meta
    mock_urlopen.side_effect = [mock_search, mock_meta]
    
    results = NpmDiscoveryProvider.discover(queries=("test mcp-server",))
    assert len(results) == 1
    assert results[0]["is_deprecated"] is True
    assert results[0]["deprecation_reason"] == "Use @mcp/v2"

@patch("urllib.request.urlopen")
def test_pypi_yanked_version_filtering(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "info": {"version": "2.0.0"},
        "releases": {
            "1.0.0": [{"yanked": False}],
            "2.0.0": [{"yanked": True}],
        }
    }).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp
    
    ver = PypiDiscoveryProvider.resolve_package_version("test-pkg")
    assert ver == "1.0.0"

@patch("urllib.request.urlopen")
def test_github_archived_and_deleted_pruning(mock_urlopen):
    import urllib.error
    
    mock_awesome = MagicMock()
    mock_awesome.__enter__.return_value.read.return_value = b"[Test mcp server Repo](https://github.com/test/repo)\n[Test mcp server Repo 2](https://github.com/test/repo2)"
    
    # First repo returns 404
    class HTTPError404(urllib.error.HTTPError):
        def __init__(self):
            super().__init__("", 404, "Not Found", {}, None)
    
    # Second repo is archived
    mock_archived = MagicMock()
    mock_archived.__enter__.return_value.read.return_value = json.dumps({"archived": True}).encode("utf-8")
    
    mock_topic = MagicMock()
    mock_topic.__enter__.return_value.read.return_value = b"{}"
    
    # Order: awesome list, first repo 404, second repo archived, topic API
    def side_effect(req, *args, **kwargs):
        if "awesome" in req.full_url:
            return mock_awesome
        elif "test/repo" in req.full_url and "repo2" not in req.full_url:
            raise HTTPError404()
        elif "test/repo2" in req.full_url:
            return mock_archived
        else:
            return mock_topic

    mock_urlopen.side_effect = side_effect
    
    results = GitHubCuratedDiscoveryProvider.discover()
    
    repo1 = next((r for r in results if r["name"] == "test/repo"), None)
    repo2 = next((r for r in results if r["name"] == "test/repo2"), None)
    
    assert repo1 is not None
    assert repo1["is_deleted"] is True
    
    assert repo2 is not None
    assert repo2["is_archived"] is True

def test_corrupt_state_recovery(tmp_path):
    state_file = tmp_path / "mcp_catalog_state.json"
    state_file.write_text("{invalid json", encoding="utf-8")
    
    state = McpCatalogState(state_file=state_file)
    assert len(state.records) == 0
    
    bak_file = state_file.with_name(state_file.name + ".corrupt.bak")
    assert bak_file.exists()

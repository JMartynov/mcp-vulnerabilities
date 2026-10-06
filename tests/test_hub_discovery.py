"""Unit tests for specialized MCP hub discovery providers (Smithery and Glama)."""

import json
from unittest.mock import MagicMock, patch
import pytest

from mcp_vulnerabilities.discovery.smithery import SmitheryDiscoveryProvider
from mcp_vulnerabilities.discovery.glama import GlamaDiscoveryProvider


def test_smithery_discovery_mock():
    mock_response = {
        "servers": [
            {
                "id": "srv-1",
                "qualifiedName": "brave-search",
                "displayName": "Brave Search Server",
                "description": "MCP server for Brave Search API",
                "homepage": "https://github.com/example/brave-mcp",
                "verified": True,
            },
            {
                "id": "srv-2",
                "qualifiedName": "scoped/custom-tool",
                "displayName": "Custom Tool",
                "description": "An MCP server for custom operations",
                "homepage": "https://example.com",
                "verified": False,
            }
        ]
    }

    mock_resp_cm = MagicMock()
    mock_resp_cm.read.return_value = json.dumps(mock_response).encode("utf-8")
    mock_resp_cm.__enter__.return_value = mock_resp_cm

    with patch("urllib.request.urlopen", return_value=mock_resp_cm):
        servers = SmitheryDiscoveryProvider.discover(max_pages=1)
        assert len(servers) == 2
        by_name = {s["name"]: s for s in servers}
        assert "@smithery/brave-search" in by_name
        assert by_name["@smithery/brave-search"]["ecosystem"] == "smithery"
        assert by_name["@smithery/brave-search"]["repository"] == "https://github.com/example/brave-mcp"
        assert "scoped/custom-tool" in by_name


def test_glama_discovery_without_token():
    # When no token is configured, should gracefully return empty list
    servers = GlamaDiscoveryProvider.discover(api_key=None)
    assert servers == []


def test_glama_discovery_with_mock_token():
    mock_response = {
        "servers": [
            {
                "id": "inst-1",
                "slug": "sqlite-explorer",
                "namespace": "acme",
                "description": "Glama-hosted SQLite MCP Server",
                "repositoryUrl": "https://github.com/acme/sqlite-mcp",
                "version": "1.2.0",
            }
        ]
    }

    mock_resp_cm = MagicMock()
    mock_resp_cm.read.return_value = json.dumps(mock_response).encode("utf-8")
    mock_resp_cm.__enter__.return_value = mock_resp_cm

    with patch("urllib.request.urlopen", return_value=mock_resp_cm):
        servers = GlamaDiscoveryProvider.discover(api_key="mock_test_token")
        assert len(servers) == 1
        assert servers[0]["name"] == "@glama/acme/sqlite-explorer"
        assert servers[0]["ecosystem"] == "glama"
        assert servers[0]["version"] == "1.2.0"

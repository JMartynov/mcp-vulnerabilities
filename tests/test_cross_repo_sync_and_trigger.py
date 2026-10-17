import os
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError
import urllib.request
import pytest

from mcp_vulnerabilities.sync_manager import CrossRepoSyncManager

def test_fetch_latest_passports_success(tmp_path):
    target_path = tmp_path / "passports.json.gz"
    manager = CrossRepoSyncManager(target_path=target_path)

    # Mock the response for the release API
    mock_release_response = MagicMock()
    mock_release_response.read.return_value = json.dumps({
        "assets": [
            {"name": "passports.json.gz", "browser_download_url": "https://example.com/passports.json.gz"}
        ]
    }).encode("utf-8")
    mock_release_response.__enter__.return_value = mock_release_response

    # Mock the response for the asset download
    mock_asset_response = MagicMock()
    mock_asset_response.read.return_value = b"test data"
    mock_asset_response.__enter__.return_value = mock_asset_response

    def mock_urlopen(req, *args, **kwargs):
        if req.full_url == manager.github_api_url:
            return mock_release_response
        elif req.full_url == "https://example.com/passports.json.gz":
            return mock_asset_response
        raise Exception(f"Unexpected URL: {req.full_url}")

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        result = manager.fetch_latest_passports()

    assert result is True
    assert target_path.exists()
    assert target_path.read_bytes() == b"test data"


def test_fetch_latest_passports_fallback_success(tmp_path):
    target_path = tmp_path / "passports.json.gz"
    manager = CrossRepoSyncManager(target_path=target_path)

    # Mock the response for the fallback download
    mock_fallback_response = MagicMock()
    mock_fallback_response.read.return_value = b"fallback data"
    mock_fallback_response.__enter__.return_value = mock_fallback_response

    def mock_urlopen(req, *args, **kwargs):
        if req.full_url == manager.github_api_url:
            raise HTTPError(req.full_url, 403, "Rate Limit", {}, None)
        elif req.full_url == "https://raw.githubusercontent.com/jmartynov/mcp-fingerprints/main/passports.json.gz":
            return mock_fallback_response
        raise Exception(f"Unexpected URL: {req.full_url}")

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        result = manager.fetch_latest_passports()

    assert result is True
    assert target_path.exists()
    assert target_path.read_bytes() == b"fallback data"


def test_fetch_latest_passports_failure(tmp_path):
    target_path = tmp_path / "passports.json.gz"
    manager = CrossRepoSyncManager(target_path=target_path)

    def mock_urlopen(req, *args, **kwargs):
        raise HTTPError(req.full_url, 404, "Not Found", {}, None)

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        result = manager.fetch_latest_passports()

    assert result is False
    assert not target_path.exists()


def test_workflow_dispatch_trigger():
    workflow_path = Path(".github/workflows/daily_sync.yml")
    assert workflow_path.exists(), "Workflow file does not exist"

    with open(workflow_path, "r") as f:
        content = f.read()

    assert "repository_dispatch" in content
    assert "upstream_fingerprints_updated" in content

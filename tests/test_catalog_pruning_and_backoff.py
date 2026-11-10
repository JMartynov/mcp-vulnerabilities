import pytest
from datetime import datetime, timezone, timedelta
from typing import Any
import json
import urllib.error
from unittest.mock import patch

from mcp_vulnerabilities.discovery.github_curated import GitHubCuratedDiscoveryProvider
from mcp_vulnerabilities.discovery.npm import NpmDiscoveryProvider


class MockHTTPError(urllib.error.HTTPError):
    def __init__(self, code):
        super().__init__("url", code, "msg", {}, None)


def test_is_repository_archived_or_pruned_with_metadata():
    # True if archived
    assert GitHubCuratedDiscoveryProvider.is_repository_archived_or_pruned("repo1", {"archived": True, "disabled": False}) is True
    # True if disabled
    assert GitHubCuratedDiscoveryProvider.is_repository_archived_or_pruned("repo2", {"archived": False, "disabled": True}) is True
    # False otherwise
    assert GitHubCuratedDiscoveryProvider.is_repository_archived_or_pruned("repo3", {"archived": False, "disabled": False}) is False


@patch('urllib.request.urlopen')
def test_is_repository_archived_or_pruned_http_404(mock_urlopen):
    # Mock HTTP 404 response
    mock_urlopen.side_effect = MockHTTPError(404)
    
    assert GitHubCuratedDiscoveryProvider.is_repository_archived_or_pruned("https://github.com/foo/bar") is True


@patch('urllib.request.urlopen')
def test_is_repository_archived_or_pruned_http_410(mock_urlopen):
    # Mock HTTP 410 response
    mock_urlopen.side_effect = MockHTTPError(410)
    
    assert GitHubCuratedDiscoveryProvider.is_repository_archived_or_pruned("https://github.com/foo/bar") is True


@patch('urllib.request.urlopen')
def test_is_repository_archived_or_pruned_http_200_archived(mock_urlopen):
    # Mock HTTP 200 response with archived metadata
    class MockResponse:
        def __init__(self, json_data):
            self.json_data = json_data
            
        def read(self):
            return json.dumps(self.json_data).encode("utf-8")
            
        def __enter__(self):
            return self
            
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    mock_urlopen.return_value = MockResponse({"archived": True})
    assert GitHubCuratedDiscoveryProvider.is_repository_archived_or_pruned("https://github.com/foo/bar") is True


@patch('urllib.request.urlopen')
def test_is_repository_archived_or_pruned_http_200_not_archived(mock_urlopen):
    class MockResponse:
        def __init__(self, json_data):
            self.json_data = json_data
            
        def read(self):
            return json.dumps(self.json_data).encode("utf-8")
            
        def __enter__(self):
            return self
            
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    mock_urlopen.return_value = MockResponse({"archived": False})
    assert GitHubCuratedDiscoveryProvider.is_repository_archived_or_pruned("https://github.com/foo/bar") is False


def test_npm_backoff_state_update():
    state = {}
    now = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    endpoint = "test_endpoint"

    # First failure
    NpmDiscoveryProvider.update_backoff_state(endpoint, state, success=False, current_time=now, base_hours=1.0)
    assert state[endpoint]["consecutive_failures"] == 1
    # Base backoff: 1 hour * (2 ** (1-1)) = 1 hour
    assert state[endpoint]["next_retry_after"] == "2023-01-01T13:00:00Z"

    # Second failure
    now2 = now + timedelta(hours=1)
    NpmDiscoveryProvider.update_backoff_state(endpoint, state, success=False, current_time=now2, base_hours=1.0)
    assert state[endpoint]["consecutive_failures"] == 2
    # Base backoff: 1 hour * (2 ** (2-1)) = 2 hours
    assert state[endpoint]["next_retry_after"] == "2023-01-01T15:00:00Z"
    
    # Success
    now3 = now2 + timedelta(hours=2)
    NpmDiscoveryProvider.update_backoff_state(endpoint, state, success=True, current_time=now3)
    assert state[endpoint]["consecutive_failures"] == 0
    assert state[endpoint]["next_retry_after"] is None


def test_npm_should_skip_due_to_backoff():
    state = {
        "test_endpoint": {
            "consecutive_failures": 1,
            "next_retry_after": "2023-01-01T13:00:00Z"
        }
    }
    endpoint = "test_endpoint"
    
    # Before retry time -> should skip
    current_time_before = datetime(2023, 1, 1, 12, 30, 0, tzinfo=timezone.utc)
    assert NpmDiscoveryProvider.should_skip_due_to_backoff(endpoint, state, current_time_before) is True
    
    # After retry time -> should NOT skip
    current_time_after = datetime(2023, 1, 1, 13, 30, 0, tzinfo=timezone.utc)
    assert NpmDiscoveryProvider.should_skip_due_to_backoff(endpoint, state, current_time_after) is False


def test_npm_backoff_max_cap():
    state = {}
    now = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    endpoint = "test_endpoint"

    # Set up failure state 
    state[endpoint] = {"consecutive_failures": 10} 
    
    # 11th failure
    NpmDiscoveryProvider.update_backoff_state(endpoint, state, success=False, current_time=now, base_hours=1.0, max_backoff_days=7.0)
    assert state[endpoint]["consecutive_failures"] == 11
    
    # 1 hour * (2 ** 10) = 1024 hours = 42.6 days
    # Should be capped at 7 days = 168 hours
    expected_retry = now + timedelta(days=7.0)
    assert state[endpoint]["next_retry_after"] == expected_retry.isoformat().replace("+00:00", "Z")


def test_cli_discover_prune_flags():
    from mcp_vulnerabilities.cli import main
    import sys
    from unittest.mock import patch
    
    test_args = ["mcp-vuln", "discover", "--prune", "--offline-backoff"]
    with patch.object(sys, 'argv', test_args):
        with patch('mcp_vulnerabilities.discovery.McpDiscoveryOrchestrator.run_discovery', autospec=True) as mock_run:
            mock_run.return_value = []
            try:
                main()
            except SystemExit:
                pass
            mock_run.assert_called_once()
            _, kwargs = mock_run.call_args
            assert kwargs.get("include_pruning") is True
            assert kwargs.get("offline_backoff") is True


def test_orchestrator_run_discovery_with_pruning_and_backoff(tmp_path):
    from mcp_vulnerabilities.discovery.orchestrator import McpDiscoveryOrchestrator
    from mcp_vulnerabilities.catalog import McpCatalogState

    catalog_file = tmp_path / "mcp_servers.json"
    state_file = tmp_path / "mcp_catalog_state.json"
    state = McpCatalogState(state_file=state_file)
    state.record_deprecation("npm", "dead-pkg", "deprecated", "No longer maintained")
    state.save()

    orchestrator = McpDiscoveryOrchestrator(catalog_file=catalog_file)
    with patch("mcp_vulnerabilities.catalog.McpCatalogState", return_value=state), \
         patch("mcp_vulnerabilities.discovery.npm.NpmDiscoveryProvider.discover") as mock_npm:
        mock_npm.return_value = [
            {"name": "alive-pkg", "ecosystem": "npm", "version": "1.0.0"},
            {"name": "dead-pkg", "ecosystem": "npm", "version": "1.0.0"},
        ]
        servers = orchestrator.run_discovery(
            include_npm=True,
            include_pypi=False,
            include_github=False,
            include_other_registries=False,
            include_smithery=False,
            include_glama=False,
            include_pruning=True,
            offline_backoff=True,
        )
        assert len(servers) == 1
        assert servers[0]["name"] == "alive-pkg"
        mock_npm.assert_called_once()
        _, npm_kwargs = mock_npm.call_args
        assert isinstance(npm_kwargs.get("backoff_state"), dict)


def test_cli_sync_prune_flags():
    from mcp_vulnerabilities.cli import main
    import sys
    from unittest.mock import patch
    
    test_args = ["mcp-vuln", "sync", "--prune"]
    with patch.object(sys, 'argv', test_args):
        with patch('mcp_vulnerabilities.pipeline.McpVulnerabilityPipeline.run', autospec=True) as mock_run:
            try:
                main()
            except SystemExit:
                pass
            mock_run.assert_called_once()
            _, kwargs = mock_run.call_args
            assert kwargs.get("include_pruning") is True


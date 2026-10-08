from mcp_vulnerabilities.catalog import McpCatalogState
from mcp_vulnerabilities.discovery.pypi import PypiDiscoveryProvider


def test_live_pypi_json_version_resolution():
    """Test resolving real package versions from PyPI."""
    version_fastmcp = PypiDiscoveryProvider.resolve_package_version("fastmcp")
    assert version_fastmcp, "Expected a version string for fastmcp"
    
    version_mcp = PypiDiscoveryProvider.resolve_package_version("mcp")
    assert version_mcp, "Expected a version string for mcp"
    
    version_mcp_server_git = PypiDiscoveryProvider.resolve_package_version("mcp-server-git")
    assert version_mcp_server_git, "Expected a version string for mcp-server-git"

    version_missing = PypiDiscoveryProvider.resolve_package_version("this-package-should-not-exist-123456")
    assert version_missing == "", "Expected empty string for non-existent package"

def test_pypi_semver_bump_triggers_re_audit(tmp_path):
    """Test catalog state management for version invalidation."""
    state_file = tmp_path / "catalog.json"
    state = McpCatalogState(state_file=state_file)
    
    state.update_record("PyPI", "fastmcp", version="0.4.0")
    
    assert state.should_query("PyPI", "fastmcp", "0.4.0") is False, "Should be warm cache for identical version"
    
    assert state.should_query("PyPI", "fastmcp", "0.4.1") is True, "Should trigger re-query on version bump"

def test_bulk_discovery_does_not_rate_limit_pypi(monkeypatch):
    """Verify that bulk discovery doesn't trigger individual requests when resolve_versions=False."""
    call_count = 0
    
    # Mock to track calls, although we could mock urllib directly.
    # It's simpler to track calls to resolve_package_version
    original_resolve = PypiDiscoveryProvider.resolve_package_version
    
    def mock_resolve(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return original_resolve(*args, **kwargs)
        
    monkeypatch.setattr(PypiDiscoveryProvider, "resolve_package_version", mock_resolve)
    
    discovered = PypiDiscoveryProvider.discover(resolve_versions=False)
    
    assert len(discovered) > 0, "Should discover at least some packages"
    assert call_count == 0, "Should not call resolve_package_version when resolve_versions=False"

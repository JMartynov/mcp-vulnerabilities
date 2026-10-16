import pytest
from mcp_vulnerabilities.audit.config_exporter import export_client_config, export_all_client_configs, SUPPORTED_CLIENTS

def test_export_claude_stdio():
    passport = {
        "package_name": "@namespace/test-pkg",
        "ecosystem": "npm",
        "versions": [
            {
                "connections": [
                    {
                        "type": "stdio",
                        "command": "node",
                        "args": ["dist/index.js"],
                        "env": {"API_KEY": "test"}
                    }
                ]
            }
        ]
    }
    
    config = export_client_config(passport, client="claude")
    assert "mcpServers" in config
    assert "namespace-test-pkg" in config["mcpServers"]
    
    server_conf = config["mcpServers"]["namespace-test-pkg"]
    assert server_conf["command"] == "node"
    assert server_conf["args"] == ["dist/index.js"]
    assert server_conf["env"] == {"API_KEY": "test"}

def test_export_cursor_sse():
    passport = {
        "package_name": "remote-pkg",
        "ecosystem": "generic",
        "versions": [
            {
                "connections": [
                    {
                        "type": "sse",
                        "url": "https://example.com/sse"
                    }
                ]
            }
        ]
    }
    
    config = export_client_config(passport, client="cursor")
    assert "mcpServers" in config
    assert "remote-pkg" in config["mcpServers"]
    
    server_conf = config["mcpServers"]["remote-pkg"]
    assert server_conf["type"] == "sse"
    assert server_conf["url"] == "https://example.com/sse"

def test_export_npm_fallback():
    passport = {
        "package_name": "simple-npm-pkg",
        "ecosystem": "npm",
        "versions": [
            {
                "connections": [
                    {
                        "type": "stdio"
                    }
                ]
            }
        ]
    }
    
    config = export_client_config(passport)
    server_conf = config["mcpServers"]["simple-npm-pkg"]
    assert server_conf["command"] == "npx"
    assert server_conf["args"] == ["-y", "simple-npm-pkg"]

def test_export_pypi_fallback():
    passport = {
        "package_name": "simple-pypi-pkg",
        "ecosystem": "pypi",
        "versions": [
            {
                "connections": [
                    {
                        "type": "stdio"
                    }
                ]
            }
        ]
    }
    
    config = export_client_config(passport)
    server_conf = config["mcpServers"]["simple-pypi-pkg"]
    assert server_conf["command"] == "uvx"
    assert server_conf["args"] == ["simple-pypi-pkg"]

def test_export_invalid_client():
    with pytest.raises(ValueError, match="Unsupported client"):
        export_client_config({"package_name": "x", "versions": [{"connections": [{"type": "stdio"}]}]}, client="unknown")
        
def test_export_no_versions():
    with pytest.raises(ValueError, match="Passport has no versions"):
        export_client_config({"package_name": "x", "versions": []})


def test_export_cline_stdio():
    passport = {
        "package_name": "cline-tool",
        "ecosystem": "npm",
        "versions": [
            {
                "connections": [
                    {
                        "type": "stdio",
                        "command": "node",
                        "args": ["server.js"],
                        "env": {"FOO": "bar"},
                    }
                ]
            }
        ]
    }
    config = export_client_config(passport, client="cline")
    assert "mcpServers" in config
    assert "cline-tool" in config["mcpServers"]
    entry = config["mcpServers"]["cline-tool"]
    assert entry["command"] == "node"
    assert entry["args"] == ["server.js"]
    assert entry["env"] == {"FOO": "bar"}
    assert entry["disabled"] is False
    assert entry["autoApprove"] == []


def test_export_cline_sse():
    passport = {
        "package_name": "cline-sse",
        "ecosystem": "generic",
        "versions": [{"connections": [{"type": "sse", "url": "https://mcp.io/sse"}]}]
    }
    config = export_client_config(passport, client="cline")
    entry = config["mcpServers"]["cline-sse"]
    assert entry["type"] == "sse"
    assert entry["url"] == "https://mcp.io/sse"
    assert entry["disabled"] is False
    assert entry["autoApprove"] == []


def test_export_zed_stdio():
    passport = {
        "package_name": "zed-tool",
        "ecosystem": "npm",
        "versions": [
            {
                "connections": [
                    {
                        "type": "stdio",
                        "command": "npx",
                        "args": ["-y", "zed-tool"],
                        "env": {"KEY": "VAL"},
                    }
                ]
            }
        ]
    }
    config = export_client_config(passport, client="zed")
    assert "context_servers" in config
    assert "zed-tool" in config["context_servers"]
    entry = config["context_servers"]["zed-tool"]
    assert "command" in entry
    assert entry["command"]["path"] == "npx"
    assert entry["command"]["args"] == ["-y", "zed-tool"]
    assert entry["command"]["env"] == {"KEY": "VAL"}


def test_export_zed_sse():
    passport = {
        "package_name": "zed-sse",
        "ecosystem": "generic",
        "versions": [{"connections": [{"type": "sse", "url": "https://mcp.io/sse"}]}]
    }
    config = export_client_config(passport, client="zed")
    entry = config["context_servers"]["zed-sse"]
    assert entry["url"] == "https://mcp.io/sse"


def test_export_windsurf_stdio():
    passport = {
        "package_name": "windsurf-tool",
        "ecosystem": "pypi",
        "versions": [
            {
                "connections": [
                    {"type": "stdio", "command": "uvx", "args": ["windsurf-tool"]}
                ]
            }
        ]
    }
    config = export_client_config(passport, client="windsurf")
    assert "mcpServers" in config
    entry = config["mcpServers"]["windsurf-tool"]
    assert entry["command"] == "uvx"
    assert entry["args"] == ["windsurf-tool"]


def test_export_docker_stdio():
    passport_npm = {
        "package_name": "npm-docker-tool",
        "ecosystem": "npm",
        "versions": [
            {
                "connections": [
                    {"type": "stdio", "command": "npx", "args": ["-y", "npm-docker-tool"], "env": {"ENV_VAR": "1"}}
                ]
            }
        ]
    }
    config_npm = export_client_config(passport_npm, client="docker")
    assert "dockerCommand" in config_npm
    assert "docker run -i --rm -e ENV_VAR=1 node:22-alpine npx -y npm-docker-tool" == config_npm["dockerCommand"]
    assert config_npm["container"]["image"] == "node:22-alpine"

    passport_pypi = {
        "package_name": "pypi-docker-tool",
        "ecosystem": "pypi",
        "versions": [
            {
                "connections": [
                    {"type": "stdio", "command": "uvx", "args": ["pypi-docker-tool"]}
                ]
            }
        ]
    }
    config_pypi = export_client_config(passport_pypi, client="docker")
    assert "docker run -i --rm python:3.12-slim uvx pypi-docker-tool" == config_pypi["dockerCommand"]
    assert config_pypi["container"]["image"] == "python:3.12-slim"


def test_export_all_client_configs():
    passport = {
        "package_name": "all-tool",
        "ecosystem": "npm",
        "versions": [
            {
                "connections": [
                    {"type": "stdio", "command": "npx", "args": ["-y", "all-tool"]}
                ]
            }
        ]
    }
    all_configs = export_all_client_configs(passport)
    for c in SUPPORTED_CLIENTS:
        assert c in all_configs


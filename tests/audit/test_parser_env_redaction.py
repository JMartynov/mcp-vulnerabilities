import json
from pathlib import Path
from mcp_vulnerabilities.audit.parsers import ClientConfigParser


def test_client_config_parser_env_redaction_refinement(tmp_path: Path):
    """Verify that benign URL config keys are not redacted while secret keys are properly redacted."""
    config_data = {
        "mcpServers": {
            "demo_server": {
                "command": "node",
                "args": ["dist/index.js"],
                "env": {
                    # Benign URL keys
                    "SERVER_URL": "https://mcp.internal.net:8443",
                    "BASE_URL": "https://api.example.com",
                    "PROXY_URL": "http://proxy.local:3128",
                    "MCP_URL": "https://mcp.hub/v1",
                    "URL": "https://service.domain/endpoint",
                    "API_URL": "https://api.domain.com/v2",
                    # Secret-bearing keys
                    "API_KEY": "super-secret-key-12345",
                    "GITHUB_TOKEN": "ghp_abcdef1234567890",
                    "CLIENT_SECRET": "client-secret-xyz",
                    "DB_PASSWORD": "my-secret-password",
                    "AUTH_HEADER": "Bearer secret-jwt-token",
                    "AWS_CREDENTIAL": "aws-cred-abc",
                    # Regular benign non-url keys
                    "NODE_ENV": "production",
                    "PORT": "8080",
                    "DEBUG": "0",
                },
            }
        }
    }
    config_file = tmp_path / "claude_desktop_config.json"
    config_file.write_text(json.dumps(config_data), encoding="utf-8")

    servers = ClientConfigParser.parse_file(config_file, "claude")
    assert len(servers) == 1
    env = servers[0].env

    # Benign URL keys must be preserved
    assert env["SERVER_URL"] == "https://mcp.internal.net:8443"
    assert env["BASE_URL"] == "https://api.example.com"
    assert env["PROXY_URL"] == "http://proxy.local:3128"
    assert env["MCP_URL"] == "https://mcp.hub/v1"
    assert env["URL"] == "https://service.domain/endpoint"
    assert env["API_URL"] == "https://api.domain.com/v2"

    # Regular non-secret keys must be preserved
    assert env["NODE_ENV"] == "production"
    assert env["PORT"] == "8080"
    assert env["DEBUG"] == "0"

    # Secret-bearing keys must be redacted
    assert env["API_KEY"] == "***REDACTED***"
    assert env["GITHUB_TOKEN"] == "***REDACTED***"
    assert env["CLIENT_SECRET"] == "***REDACTED***"
    assert env["DB_PASSWORD"] == "***REDACTED***"
    assert env["AUTH_HEADER"] == "***REDACTED***"
    assert env["AWS_CREDENTIAL"] == "***REDACTED***"

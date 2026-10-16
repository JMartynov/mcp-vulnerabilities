"""Unit tests for the Automated Conflict Resolver."""

import json
import sys

import pytest

from mcp_vulnerabilities.audit.conflict_resolver import resolve_client_config


@pytest.fixture
def mock_passport_dir(tmp_path):
    p_dir = tmp_path / "passports"
    p_dir.mkdir(parents=True)

    server1 = {
        "package_name": "@modelcontextprotocol/server-filesystem",
        "ecosystem": "npm",
        "versions": [
            {
                "version": "1.0.0",
                "tool_signatures": [
                    {
                        "name": "read_file",
                        "canonical_hash": "sha256:hash_read_1",
                        "description": "Read file",
                        "property_keys": ["path"],
                        "required_keys": ["path"],
                        "parameter_types": {"path": "string"},
                        "inputSchema": {"properties": {"path": {"type": "string"}}},
                    }
                ],
            }
        ],
    }
    with open(p_dir / "server_filesystem.json", "w", encoding="utf-8") as f:
        json.dump(server1, f)

    server3 = {
        "package_name": "rogue-file-manager",
        "ecosystem": "npm",
        "versions": [
            {
                "version": "1.0.0",
                "tool_signatures": [
                    {
                        "name": "read_file",
                        "canonical_hash": "sha256:hash_read_divergent",
                        "description": "Custom file reader",
                        "property_keys": ["file_url"],
                        "required_keys": ["file_url"],
                        "parameter_types": {"file_url": "string"},
                        "inputSchema": {"properties": {"file_url": {"type": "string"}}},
                    },
                    {
                        "name": "unique_rogue_tool",
                        "canonical_hash": "sha256:hash_unique",
                        "description": "Unique tool",
                        "property_keys": ["data"],
                        "required_keys": ["data"],
                        "parameter_types": {"data": "string"},
                        "inputSchema": {"properties": {"data": {"type": "string"}}},
                    },
                ],
            }
        ],
    }
    with open(p_dir / "server_rogue.json", "w", encoding="utf-8") as f:
        json.dump(server3, f)

    return p_dir


def test_resolve_strategy_prefix(mock_passport_dir, tmp_path):
    config = {
        "mcpServers": {
            "official_fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem"],
            },
            "rogue_fs": {"command": "npx", "args": ["-y", "rogue-file-manager"]},
        }
    }
    conf_path = tmp_path / "colliding_config.json"
    conf_path.write_text(json.dumps(config))

    result = resolve_client_config(
        conf_path, strategy="prefix", passports_dir=mock_passport_dir
    )
    assert result.strategy_used == "prefix"
    assert len(result.modifications_made) > 0
    assert not result.audit_report.is_clean

    servers = result.resolved_config["mcpServers"]
    # Check that both servers have environment variables and args added for prefixing the conflicting tool
    assert "MCP_PREFIX_READ_FILE" in servers["official_fs"]["env"]
    assert servers["official_fs"]["env"]["MCP_PREFIX_READ_FILE"] == "official_fs__"
    assert "--prefix=official_fs__" in servers["official_fs"]["args"]

    assert "MCP_PREFIX_READ_FILE" in servers["rogue_fs"]["env"]
    assert servers["rogue_fs"]["env"]["MCP_PREFIX_READ_FILE"] == "rogue_fs__"
    assert "--prefix=rogue_fs__" in servers["rogue_fs"]["args"]


def test_resolve_strategy_priority(mock_passport_dir, tmp_path):
    config = {
        "mcpServers": {
            "official_fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem"],
            },
            "rogue_fs": {"command": "npx", "args": ["-y", "rogue-file-manager"]},
        }
    }
    conf_path = tmp_path / "colliding_config.json"
    conf_path.write_text(json.dumps(config))

    result = resolve_client_config(
        conf_path, strategy="priority", passports_dir=mock_passport_dir
    )
    assert result.strategy_used == "priority"

    servers = result.resolved_config["mcpServers"]

    # Priority uses the first server, meaning official_fs keeps it, rogue_fs disables it
    assert "disabledTools" not in servers["official_fs"] or "read_file" not in servers[
        "official_fs"
    ].get("disabledTools", [])

    assert "disabledTools" in servers["rogue_fs"]
    assert "read_file" in servers["rogue_fs"]["disabledTools"]


def test_resolve_strategy_report(mock_passport_dir, tmp_path):
    config = {
        "mcpServers": {
            "official_fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem"],
            },
            "rogue_fs": {"command": "npx", "args": ["-y", "rogue-file-manager"]},
        }
    }
    conf_path = tmp_path / "colliding_config.json"
    conf_path.write_text(json.dumps(config))

    result = resolve_client_config(
        conf_path, strategy="report", passports_dir=mock_passport_dir
    )
    assert result.strategy_used == "report"
    assert len(result.modifications_made) == 0
    assert result.resolved_config == result.original_config


def test_resolve_non_colliding_preservation(mock_passport_dir, tmp_path):
    # A config without collisions should not be modified
    config = {
        "mcpServers": {
            "official_fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem"],
            },
        }
    }
    conf_path = tmp_path / "clean_config.json"
    conf_path.write_text(json.dumps(config))

    for strategy in ["prefix", "priority", "report"]:
        result = resolve_client_config(
            conf_path, strategy=strategy, passports_dir=mock_passport_dir
        )
        assert result.resolved_config == result.original_config


def test_cli_roundtrip(mock_passport_dir, tmp_path):
    config = {
        "mcpServers": {
            "official_fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem"],
            },
            "rogue_fs": {"command": "npx", "args": ["-y", "rogue-file-manager"]},
        }
    }
    conf_path = tmp_path / "colliding_config.json"
    out_path = tmp_path / "resolved_config.json"
    conf_path.write_text(json.dumps(config))

    resolve_client_config(
        conf_path,
        strategy="priority",
        output_path=out_path,
        passports_dir=mock_passport_dir,
    )

    assert out_path.exists()
    resolved = json.loads(out_path.read_text())
    assert "read_file" in resolved["mcpServers"]["rogue_fs"]["disabledTools"]


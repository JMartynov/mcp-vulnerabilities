"""ATDD unit tests for AC-105.1: Conflict Resolver Flag Injection."""

import json

from mcp_vulnerabilities.audit.conflict_resolver import resolve_client_config


def _write_mock_passports(passports_dir):
    passports_dir.mkdir(parents=True, exist_ok=True)
    server_a = {
        "package_name": "pkg-alpha",
        "ecosystem": "npm",
        "versions": [
            {
                "version": "1.0.0",
                "tool_signatures": [
                    {
                        "name": "read_file",
                        "canonical_hash": "sha256:alpha_read",
                        "description": "Read file alpha",
                        "property_keys": ["path"],
                        "required_keys": ["path"],
                        "parameter_types": {"path": "string"},
                        "inputSchema": {"properties": {"path": {"type": "string"}}},
                    }
                ],
            }
        ],
    }
    server_b = {
        "package_name": "pkg-beta",
        "ecosystem": "npm",
        "versions": [
            {
                "version": "1.0.0",
                "tool_signatures": [
                    {
                        "name": "read_file",
                        "canonical_hash": "sha256:beta_read",
                        "description": "Read file beta",
                        "property_keys": ["target"],
                        "required_keys": ["target"],
                        "parameter_types": {"target": "string"},
                        "inputSchema": {"properties": {"target": {"type": "string"}}},
                    }
                ],
            }
        ],
    }
    (passports_dir / "alpha.json").write_text(json.dumps(server_a), encoding="utf-8")
    (passports_dir / "beta.json").write_text(json.dumps(server_b), encoding="utf-8")
    return passports_dir


def test_no_prefix_flag_injected(tmp_path):
    """AC-105.1: Colliding server keys must not inject --prefix= into server args."""
    passports_dir = _write_mock_passports(tmp_path / "passports")
    config = {
        "mcpServers": {
            "alpha_srv": {"command": "npx", "args": ["-y", "pkg-alpha"]},
            "beta_srv": {"command": "uvx", "args": ["pkg-beta"]},
        }
    }
    conf_path = tmp_path / "mcp.json"
    conf_path.write_text(json.dumps(config), encoding="utf-8")

    result = resolve_client_config(
        conf_path, strategy="prefix", passports_dir=passports_dir
    )
    servers = result.resolved_config["mcpServers"]

    assert len(servers) == len(set(servers.keys())) == 2
    for server_name, s_conf in servers.items():
        args = s_conf.get("args", [])
        assert not any(str(a).startswith("--prefix=") for a in args), (
            f"Unexpected --prefix= flag in args for {server_name}: {args}"
        )
        assert "MCP_PREFIX_READ_FILE" in s_conf.get("env", {})
        assert s_conf["env"]["MCP_PREFIX_READ_FILE"] == f"{server_name}__"

    assert servers["alpha_srv"]["args"] == ["-y", "pkg-alpha"]
    assert servers["beta_srv"]["args"] == ["pkg-beta"]


def test_non_conflicting_config_passthrough(tmp_path):
    """AC-105.1 paired benign control: non-conflicting config is emitted unmodified."""
    passports_dir = _write_mock_passports(tmp_path / "passports")
    config = {
        "mcpServers": {
            "alpha_srv": {"command": "npx", "args": ["-y", "pkg-alpha"]},
        }
    }
    raw_text = json.dumps(config, indent=2) + "\n"
    conf_path = tmp_path / "clean_mcp.json"
    out_path = tmp_path / "out_mcp.json"
    conf_path.write_text(raw_text, encoding="utf-8")

    result = resolve_client_config(
        conf_path,
        strategy="prefix",
        output_path=out_path,
        passports_dir=passports_dir,
    )
    assert result.audit_report.is_clean is True
    assert result.modifications_made == []
    assert result.resolved_config == result.original_config
    assert out_path.read_text(encoding="utf-8") == raw_text

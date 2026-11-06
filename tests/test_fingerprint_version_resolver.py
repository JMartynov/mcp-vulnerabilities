"""Unit tests for FingerprintVersionResolver and audit version enrichment."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_vulnerabilities.audit.matcher import AuditReport, VulnerabilityMatcher
from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer
from mcp_vulnerabilities.fingerprints.resolver import FingerprintVersionResolver


def test_resolve_from_npx_cache(tmp_path: Path):
    resolver = FingerprintVersionResolver()
    resolver._npx_cache = [
        {
            "name": "chrome-devtools-mcp",
            "version": "1.12.0",
            "client": "npx-cache",
            "source": str(tmp_path / "package.json"),
        }
    ]

    server = DiscoveredClientServer(
        server_name="chrome-devtools-mcp",
        package_name="chrome-devtools-mcp",
        version="latest",
        ecosystem="npm",
        command="npx",
        args=["-y", "chrome-devtools-mcp@latest"],
    )

    ver, src = resolver.resolve_server_version(server)
    assert ver == "1.12.0"
    assert src == "npx-cache"


def test_resolve_from_node_package_json(tmp_path: Path):
    pkg_dir = tmp_path / "my-extension" / "mcp-server"
    pkg_dir.mkdir(parents=True)
    pkg_json = pkg_dir / "package.json"
    pkg_json.write_text(json.dumps({"name": "test-server", "version": "2.4.1"}))

    script_path = pkg_dir / "dist" / "index.js"
    script_path.parent.mkdir(parents=True)
    script_path.write_text("// server code")

    resolver = FingerprintVersionResolver()
    resolver._npx_cache = []

    server = DiscoveredClientServer(
        server_name="test-server",
        package_name="test-server",
        version=None,
        ecosystem="npm",
        command="node",
        args=[str(script_path)],
    )

    ver, src = resolver.resolve_server_version(server)
    assert ver == "2.4.1"
    assert src == "package.json"


def test_resolve_from_python_pyproject(tmp_path: Path):
    proj_dir = tmp_path / "my_py_mcp"
    proj_dir.mkdir(parents=True)
    (proj_dir / "pyproject.toml").write_text('[project]\nname = "my-py-mcp"\nversion = "0.5.2"\n')

    venv_bin = proj_dir / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    fake_python = venv_bin / "python3"
    fake_python.write_text("#!/bin/sh\n")

    resolver = FingerprintVersionResolver()
    resolver._npx_cache = []

    server = DiscoveredClientServer(
        server_name="my-py-mcp",
        package_name="my.py.mcp",
        version=None,
        ecosystem="PyPI",
        command=str(fake_python),
        args=["-m", "my.py.mcp"],
    )

    ver, src = resolver.resolve_server_version(server)
    assert ver == "0.5.2"
    assert src == "pyproject.toml"


def test_enrich_servers_preserves_pinned():
    resolver = FingerprintVersionResolver()
    resolver._npx_cache = [
        {"name": "foo", "version": "2.0.0", "client": "npx-cache", "source": "/tmp"}
    ]

    pinned_server = DiscoveredClientServer(
        server_name="foo",
        package_name="foo",
        version="1.0.0",
        ecosystem="npm",
        command="npx",
        args=["foo@1.0.0"],
    )

    unpinned_server = DiscoveredClientServer(
        server_name="foo",
        package_name="foo",
        version=None,
        ecosystem="npm",
        command="npx",
        args=["foo"],
    )

    servers = [pinned_server, unpinned_server]
    enriched = resolver.enrich_servers(servers)

    # Pinned remains untouched
    assert enriched[0].version == "1.0.0"
    assert enriched[0].resolution_source is None

    # Unpinned gets resolved
    assert enriched[1].version == "2.0.0"
    assert enriched[1].original_version is None
    assert enriched[1].resolution_source == "npx-cache"


def test_audit_report_to_dict_includes_resolution_source():
    server = DiscoveredClientServer(
        server_name="demo-server",
        package_name="demo-package",
        version="1.2.3",
        ecosystem="npm",
        command="npx",
        args=["demo-package"],
        original_version="latest",
        resolution_source="npx-cache",
    )

    report = AuditReport(scanned_servers=[server], findings=[])
    data = report.to_dict()

    assert len(data["servers"]) == 1
    srv_data = data["servers"][0]
    assert srv_data["name"] == "demo-server"
    assert srv_data["version"] == "1.2.3"
    assert srv_data["original_version"] == "latest"
    assert srv_data["resolution_source"] == "npx-cache"

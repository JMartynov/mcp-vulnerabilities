"""Unit and integration tests for MCP Client Security Auditor."""

import json
from pathlib import Path

from mcp_vulnerabilities.audit.fixer import ClientConfigFixer
from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher
from mcp_vulnerabilities.audit.parsers import ClientConfigParser, DiscoveredClientServer


def test_client_config_parser_claude_desktop(tmp_path: Path):
    config_file = tmp_path / "claude_desktop_config.json"
    config_data = {
        "mcpServers": {
            "neo4j": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-neo4j@0.6.1"]
            },
            "git": {
                "command": "uvx",
                "args": ["mcp-server-git==0.1.0"]
            },
            "sqlite": {
                "command": "python",
                "args": ["-m", "mcp_server_sqlite"]
            },
            "unpinned": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-filesystem", "/tmp"]
            },
            "docker_srv": {
                "command": "docker",
                "args": ["run", "-i", "--rm", "mcp/fetch:v1.0.0"]
            }
        }
    }
    config_file.write_text(json.dumps(config_data), encoding="utf-8")

    servers = ClientConfigParser.parse_file(config_file)
    assert len(servers) == 5

    by_name = {s.server_name: s for s in servers}
    assert by_name["neo4j"].package_name == "@modelcontextprotocol/server-neo4j"
    assert by_name["neo4j"].version == "0.6.1"
    assert by_name["neo4j"].ecosystem == "npm"

    assert by_name["git"].package_name == "mcp-server-git"
    assert by_name["git"].version == "0.1.0"
    assert by_name["git"].ecosystem == "PyPI"

    assert by_name["sqlite"].package_name == "mcp-server-sqlite"
    assert by_name["sqlite"].ecosystem == "PyPI"
    assert by_name["sqlite"].version is None

    assert by_name["unpinned"].package_name == "@modelcontextprotocol/server-filesystem"
    assert by_name["unpinned"].version is None

    assert by_name["docker_srv"].package_name == "mcp/fetch"
    assert by_name["docker_srv"].version == "v1.0.0"
    assert by_name["docker_srv"].ecosystem == "Docker"


def test_vulnerability_matcher_confirmed_vulnerable():
    mock_advisory = {
        "id": "TEST-VULN-001",
        "summary": "Mock SQL Injection in test server",
        "affected": [
            {
                "package": {
                    "name": "test-mcp-server",
                    "ecosystem": "PyPI",
                },
                "database_specific": {
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                },
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.5.0"}
                        ]
                    }
                ]
            }
        ]
    }

    matcher = VulnerabilityMatcher([mock_advisory])

    vuln_server = DiscoveredClientServer(
        server_name="test_srv",
        package_name="test-mcp-server",
        version="1.2.0",
        ecosystem="PyPI",
        command="python",
        args=["-m", "test_mcp_server"],
    )

    report = matcher.audit_servers([vuln_server])
    assert report.total_findings == 1
    assert report.has_critical_or_high is True
    finding = report.findings[0]
    assert finding.vulnerability_id == "TEST-VULN-001"
    assert finding.is_confirmed is True
    assert finding.severity_level == "CRITICAL"
    assert finding.fixed_version == "1.5.0"


def test_vulnerability_matcher_patched_clean():
    mock_advisory = {
        "id": "TEST-VULN-001",
        "summary": "Mock SQL Injection",
        "affected": [
            {
                "package": {
                    "name": "test-mcp-server",
                    "ecosystem": "PyPI",
                },
                "database_specific": {"severity": "HIGH"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.5.0"}
                        ]
                    }
                ]
            }
        ]
    }

    matcher = VulnerabilityMatcher([mock_advisory])

    safe_server = DiscoveredClientServer(
        server_name="test_srv",
        package_name="test-mcp-server",
        version="1.5.0",
        ecosystem="PyPI",
        command="python",
        args=[],
    )

    report = matcher.audit_servers([safe_server])
    assert report.total_findings == 0
    assert report.has_critical_or_high is False


def test_vulnerability_matcher_unpinned_warning():
    mock_advisory = {
        "id": "TEST-VULN-002",
        "summary": "Mock RCE in unpinned server",
        "affected": [
            {
                "package": {
                    "name": "unpinned-server",
                    "ecosystem": "npm",
                },
                "database_specific": {"severity": "CRITICAL"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.0.0"}
                        ]
                    }
                ]
            }
        ]
    }

    matcher = VulnerabilityMatcher([mock_advisory])

    unpinned_server = DiscoveredClientServer(
        server_name="unpinned",
        package_name="unpinned-server",
        version=None,
        ecosystem="npm",
        command="npx",
        args=["unpinned-server"],
    )

    report = matcher.audit_servers([unpinned_server])
    assert report.total_findings == 1
    assert report.findings[0].is_confirmed is False
    assert report.findings[0].fixed_version == "2.0.0"


def test_vulnerability_matcher_from_canonical_database():
    data_dir = Path("data/vulnerabilities")
    assert data_dir.exists()

    matcher = VulnerabilityMatcher.from_directory(data_dir)
    assert len(matcher.advisories) > 0

    # Audit known vulnerable Neo4j Cypher server
    vuln_server = DiscoveredClientServer(
        server_name="neo4j",
        package_name="mcp-neo4j-cypher",
        version="0.3.0",
        ecosystem="PyPI",
        command="manual",
        args=[],
    )

    report = matcher.audit_servers([vuln_server])
    assert report.total_findings >= 1
    cve_ids = [f.vulnerability_id for f in report.findings]
    assert "CVE-2025-10193" in cve_ids

def test_client_config_fixer(tmp_path: Path):
    mock_advisories = [
        {
            "id": "TEST-VULN-001",
            "summary": "NPM Vulnerability",
            "affected": [
                {
                    "package": {
                        "name": "@modelcontextprotocol/server-postgres",
                        "ecosystem": "npm",
                    },
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "0.6.2"}
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "TEST-VULN-002",
            "summary": "PyPI Vulnerability",
            "affected": [
                {
                    "package": {
                        "name": "mcp-server-sqlite",
                        "ecosystem": "PyPI",
                    },
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "0.2.0"}
                            ]
                        }
                    ]
                }
            ]
        }
    ]

    matcher = VulnerabilityMatcher(mock_advisories)
    fixer = ClientConfigFixer(matcher)

    config_file = tmp_path / "claude_desktop_config.json"
    config_data = {
        "mcpServers": {
            "postgres": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.1"]
            },
            "sqlite": {
                "command": "uvx",
                "args": ["mcp-server-sqlite==0.1.0"]
            },
            "safe_server": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.2"]
            }
        }
    }
    config_file.write_text(json.dumps(config_data), encoding="utf-8")

    # Dry run
    result_dry = fixer.fix_config(config_file, dry_run=True)
    assert result_dry["status"] == "dry_run"
    assert len(result_dry["changes"]) == 2
    
    # Check that file is unchanged
    with open(config_file, "r") as f:
        data = json.load(f)
    assert data["mcpServers"]["postgres"]["args"][1] == "@modelcontextprotocol/server-postgres@0.6.1"

    # Actual fix
    result_fix = fixer.fix_config(config_file, dry_run=False)
    assert result_fix["status"] == "success"
    assert len(result_fix["changes"]) == 2
    assert "backup_path" in result_fix
    
    # Verify backup was created
    assert Path(result_fix["backup_path"]).exists()
    
    # Verify file was updated
    with open(config_file, "r") as f:
        updated_data = json.load(f)
        
    assert updated_data["mcpServers"]["postgres"]["args"][1] == "@modelcontextprotocol/server-postgres@0.6.2"
    assert updated_data["mcpServers"]["sqlite"]["args"][0] == "mcp-server-sqlite==0.2.0"
    assert updated_data["mcpServers"]["safe_server"]["args"][1] == "@modelcontextprotocol/server-postgres@0.6.2"


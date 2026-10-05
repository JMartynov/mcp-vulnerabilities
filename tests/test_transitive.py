"""Unit tests for Transitive Dependency Auditor."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from mcp_vulnerabilities.transitive import TransitiveDependencyAuditor, TransitiveAuditResult


def test_parse_package_json(tmp_path: Path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        json.dumps({
            "name": "sample-mcp-server",
            "dependencies": {
                "express": "^4.17.1",
                "axios": "~0.21.1",
            },
            "devDependencies": {
                "typescript": "^5.0.0"
            }
        }),
        encoding="utf-8"
    )

    deps = TransitiveDependencyAuditor.parse_package_json(pkg_json)
    by_name = {d[0]: (d[1], d[2]) for d in deps}

    assert "express" in by_name
    assert by_name["express"][0] == "4.17.1"
    assert by_name["express"][1] == "npm"

    assert "axios" in by_name
    assert by_name["axios"][0] == "0.21.1"


def test_parse_requirements_txt(tmp_path: Path):
    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text(
        """
        # Production dependencies
        mcp>=0.1.0
        requests==2.25.1
        urllib3<1.26.5
        fastapi
        """,
        encoding="utf-8"
    )

    deps = TransitiveDependencyAuditor.parse_requirements_txt(req_txt)
    by_name = {d[0]: (d[1], d[2]) for d in deps}

    assert "mcp" in by_name
    assert by_name["mcp"][0] == "0.1.0"
    assert by_name["mcp"][1] == "PyPI"

    assert "requests" in by_name
    assert by_name["requests"][0] == "2.25.1"

    assert "fastapi" in by_name
    assert by_name["fastapi"][0] is None


def test_audit_dependencies_mock():
    mock_osv_response = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-cph5-m8f7-6c5x",
                        "summary": "Prototype pollution in express",
                        "database_specific": {"severity": "HIGH"},
                        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                        "affected": [
                            {
                                "ranges": [
                                    {"events": [{"introduced": "0"}, {"fixed": "4.19.2"}]}
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }

    mock_resp_cm = MagicMock()
    mock_resp_cm.read.return_value = json.dumps(mock_osv_response).encode("utf-8")
    mock_resp_cm.__enter__.return_value = mock_resp_cm

    with patch("urllib.request.urlopen", return_value=mock_resp_cm):
        findings = TransitiveDependencyAuditor.audit_dependencies([("express", "4.17.1", "npm")])
        assert len(findings) == 1
        f = findings[0]
        assert f.dependency_name == "express"
        assert f.vulnerability_id == "GHSA-cph5-m8f7-6c5x"
        assert f.severity == "HIGH"
        assert f.cvss_score == 7.5
        assert f.fixed_version == "4.19.2"

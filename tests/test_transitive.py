"""Unit tests for Transitive Dependency Auditor."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from mcp_vulnerabilities.transitive import TransitiveDependencyAuditor


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


def test_parse_pyproject_toml(tmp_path: Path):
    toml_path = tmp_path / "pyproject.toml"
    toml_path.write_text(
        """
        [project]
        name = "my-mcp"
        dependencies = [
            "fastapi[all]>=0.95.0",
            "pydantic",
            "httpx>=0.23.0",
            "django^4.2"
        ]
        
        [project.optional-dependencies]
        dev = ["pytest>=7.0.0"]
        """,
        encoding="utf-8"
    )

    deps = TransitiveDependencyAuditor.parse_pyproject_toml(toml_path)
    by_name = {d[0]: (d[1], d[2]) for d in deps}

    assert "fastapi" in by_name
    assert by_name["fastapi"][0] == "0.95.0"
    assert by_name["fastapi"][1] == "PyPI"

    assert "pydantic" in by_name
    assert by_name["pydantic"][0] is None

    assert "httpx" in by_name
    assert by_name["httpx"][0] == "0.23.0"

    assert "pytest" in by_name
    assert by_name["pytest"][0] == "7.0.0"

    assert "django" in by_name
    assert by_name["django"][0] == "4.2"


def test_parse_uv_lock(tmp_path: Path):
    lock_path = tmp_path / "uv.lock"
    lock_path.write_text(
        """
        version = 1

        [[package]]
        name = "fastapi"
        version = "0.95.1"

        [[package]]
        name = "pydantic"
        version = "1.10.7"
        """,
        encoding="utf-8"
    )

    deps = TransitiveDependencyAuditor.parse_uv_lock(lock_path)
    by_name = {d[0]: (d[1], d[2]) for d in deps}

    assert "fastapi" in by_name
    assert by_name["fastapi"][0] == "0.95.1"
    assert by_name["fastapi"][1] == "PyPI"

    assert "pydantic" in by_name
    assert by_name["pydantic"][0] == "1.10.7"


def test_parse_poetry_lock(tmp_path: Path):
    lock_path = tmp_path / "poetry.lock"
    lock_path.write_text(
        """
        [[package]]
        name = "httpx"
        version = "0.24.1"
        description = "The next generation HTTP client."

        [[package]]
        name = "certifi"
        version = "2023.5.7"
        """,
        encoding="utf-8"
    )

    deps = TransitiveDependencyAuditor.parse_poetry_lock(lock_path)
    by_name = {d[0]: (d[1], d[2]) for d in deps}

    assert "httpx" in by_name
    assert by_name["httpx"][0] == "0.24.1"
    assert by_name["httpx"][1] == "PyPI"

    assert "certifi" in by_name
    assert by_name["certifi"][0] == "2023.5.7"


def test_audit_manifest_file_dispatch(tmp_path: Path):
    # Test dispatching mechanism
    lock_path = tmp_path / "uv.lock"
    lock_path.write_text(
        """
        [[package]]
        name = "some-pkg"
        version = "1.0.0"
        """,
        encoding="utf-8"
    )
    
    with patch.object(TransitiveDependencyAuditor, "audit_dependencies", return_value=[]) as mock_audit:
        res = TransitiveDependencyAuditor.audit_manifest_file(lock_path)
        assert res.total_dependencies == 1
        mock_audit.assert_called_once()


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

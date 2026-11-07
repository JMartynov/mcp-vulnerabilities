import json
import pytest
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

from mcp_vulnerabilities.scanners.trivy_engine import TrivyScanner, VulnerabilityFinding, TrivyScanResult

@pytest.fixture
def scanner():
    return TrivyScanner()

def test_trivy_scanner_mocked_fs(scanner):
    mock_output = json.dumps({
        "Results": [
            {
                "Target": "package.json",
                "Class": "lang-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-1234",
                        "PkgName": "express",
                        "InstalledVersion": "4.17.1",
                        "FixedVersion": "4.17.3",
                        "Severity": "HIGH",
                        "Title": "Denial of Service in express",
                        "References": ["https://example.com/cve-2023-1234"]
                    }
                ]
            }
        ]
    })
    
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=mock_output)
        
        result = scanner.scan_fs("/tmp/mock")
        findings = result.findings
        
        assert isinstance(result, TrivyScanResult)
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2023-1234"
        assert findings[0].package_name == "express"

def test_trivy_scanner_empty_output(scanner):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="")
        
        result = scanner.scan_fs("/tmp/mock")
        assert len(result.findings) == 0

@pytest.mark.integration
@pytest.mark.skipif(shutil.which("trivy") is None, reason="trivy binary not found in PATH")
def test_scan_fs_integration_multiple(scanner, tmp_path):
    # Example 1: Empty dir
    res1 = scanner.scan_fs(tmp_path)
    assert isinstance(res1, TrivyScanResult)
    
    # Example 2: Dummy package.json
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"name": "test1", "dependencies": {"express": "4.17.1"}}))
    res2 = scanner.scan_fs(tmp_path)
    assert isinstance(res2, TrivyScanResult)
    
    # Example 3: Python requirements.txt
    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text("requests==2.20.0\n")
    res3 = scanner.scan_fs(tmp_path)
    assert isinstance(res3, TrivyScanResult)
    
    # Example 4: Dummy poetry.lock
    poetry_lock = tmp_path / "poetry.lock"
    poetry_lock.write_text("dummy lock content")
    res4 = scanner.scan_fs(tmp_path)
    assert isinstance(res4, TrivyScanResult)
    
    # Example 5: This repository
    res5 = scanner.scan_fs(Path("."))
    assert isinstance(res5, TrivyScanResult)

@pytest.mark.integration
@pytest.mark.skipif(shutil.which("trivy") is None, reason="trivy binary not found in PATH")
def test_scan_registry_integration_multiple(scanner):
    # Mode B Examples
    # 1. npm: express (vulnerable version)
    res1 = scanner.scan_npm_package("express", "4.17.1")
    assert isinstance(res1, TrivyScanResult)
    
    # 2. npm: lodash (vulnerable version)
    res2 = scanner.scan_npm_package("lodash", "4.17.20")
    assert isinstance(res2, TrivyScanResult)
    
    # 3. npm: debug (safe/modern version)
    res3 = scanner.scan_npm_package("debug", "4.3.4")
    assert isinstance(res3, TrivyScanResult)
    
    # 4. PyPI: requests (vulnerable version)
    res4 = scanner.scan_pypi_package("requests", "2.20.0")
    assert isinstance(res4, TrivyScanResult)
    
    # 5. PyPI: urllib3 (vulnerable version)
    res5 = scanner.scan_pypi_package("urllib3", "1.25.8")
    assert isinstance(res5, TrivyScanResult)

@pytest.mark.integration
@pytest.mark.skipif(shutil.which("trivy") is None, reason="trivy binary not found in PATH")
def test_scan_image_integration_multiple(scanner):
    # Mode C Examples
    # 1. alpine:3.10 (Highly vulnerable)
    res1 = scanner.scan_image("alpine:3.10")
    assert isinstance(res1, TrivyScanResult)
    assert len(res1.findings) > 0
    
    # 2. alpine:latest (Usually clean)
    res2 = scanner.scan_image("alpine:latest")
    assert isinstance(res2, TrivyScanResult)
    
    # 3. nginx:1.18-alpine (Known vulns)
    res3 = scanner.scan_image("nginx:1.18-alpine")
    assert isinstance(res3, TrivyScanResult)
    
    # 4. busybox:1.31 (Old version)
    res4 = scanner.scan_image("busybox:1.31")
    assert isinstance(res4, TrivyScanResult)
    
    # 5. hello-world (Minimal/Zero vulns)
    res5 = scanner.scan_image("hello-world")
    assert isinstance(res5, TrivyScanResult)


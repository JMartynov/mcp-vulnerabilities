import gzip
import json
import zipfile
from pathlib import Path

import subprocess
import sys
import tarfile

from mcp_vulnerabilities.snapshot import (
    build_snapshot,
    export_airgap_bundle,
    export_osv_bucket,
)


def test_build_snapshot(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "GHSA-1234.json").write_text(
        json.dumps({
            "id": "GHSA-1234",
            "schema_version": "1.6.0",
            "summary": "Test vulnerability",
            "affected": []
        }),
        encoding="utf-8"
    )
    
    out_gz = tmp_path / "vulnerabilities.json.gz"
    res = build_snapshot(data_dir=data_dir, output_gz=out_gz)
    
    assert res["total_vulnerabilities"] == 1
    assert out_gz.is_file()
    
    with gzip.open(out_gz, "rt", encoding="utf-8") as f:
        data = json.load(f)
    assert data["total_vulnerabilities"] == 1
    assert "GHSA-1234" in data["vulnerabilities"]

def test_export_airgap_bundle(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "GHSA-1234.json").write_text(
        json.dumps({
            "id": "GHSA-1234",
            "schema_version": "1.6.0",
            "summary": "Test vulnerability",
            "affected": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "npm"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]
                }
            ]
        }),
        encoding="utf-8"
    )
    
    out_tar = tmp_path / "dist" / "mcp-offline.tar.gz"
    res = export_airgap_bundle(data_dir=data_dir, output_tar=out_tar)
    
    assert Path(res["bundle_path"]).exists()
    assert Path(res["checksum_path"]).exists()
    
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()
    
    with tarfile.open(res["bundle_path"], "r:gz") as tar:
        tar.extractall(path=extract_dir, filter="data")
        
    assert (extract_dir / "vulnerabilities.json.gz").exists()
    assert (extract_dir / "query.py").exists()
    assert (extract_dir / "data" / "vulnerabilities" / "GHSA-1234.json").exists()
    
    # Run the embedded query.py script with a vulnerable version
    proc_vuln = subprocess.run(
        [sys.executable, "query.py", "--package", "test-pkg@0.5.0"],
        cwd=extract_dir,
        capture_output=True,
        text=True
    )
    assert proc_vuln.returncode == 1
    assert "VULNERABILITIES FOUND FOR test-pkg@0.5.0" in proc_vuln.stdout
    assert "GHSA-1234" in proc_vuln.stdout
    
    # Run the embedded query.py script with a non-vulnerable version
    proc_safe = subprocess.run(
        [sys.executable, "query.py", "--package", "test-pkg@1.2.0"],
        cwd=extract_dir,
        capture_output=True,
        text=True
    )
    assert proc_safe.returncode == 0
    assert "No vulnerabilities found for test-pkg@1.2.0" in proc_safe.stdout


def test_export_osv_bucket(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    out_dir = tmp_path / "dist" / "osv"
    
    # Valid OSV vulnerability
    valid_content = {
        "id": "GHSA-1234",
        "schema_version": "1.6.0",
        "published": "2023-01-01T00:00:00Z",
        "modified": "2023-01-01T00:00:00Z",
        "summary": "Test vulnerability",
        "details": "A test details string",
        "affected": [
            {
                "package": {
                    "name": "mcp-test",
                    "ecosystem": "npm"
                },
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"}
                        ]
                    }
                ]
            }
        ]
    }
    (data_dir / "GHSA-1234.json").write_text(json.dumps(valid_content), encoding="utf-8")
    
    # Invalid (missing details)
    invalid_content = {
        "id": "GHSA-5678",
        "schema_version": "1.6.0",
        "summary": "Missing fields",
        "affected": []
    }
    (data_dir / "GHSA-5678.json").write_text(json.dumps(invalid_content), encoding="utf-8")
    
    res = export_osv_bucket(data_dir=data_dir, output_dir=out_dir)
    
    # Only the valid one should be included
    assert res["count"] == 1
    assert "sha256" in res
    assert "updated" in res
    
    zip_path = out_dir / "all.zip"
    manifest_path = out_dir / "manifest.json"
    
    assert zip_path.is_file()
    assert manifest_path.is_file()
    
    # Check manifest contents
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest_data["count"] == 1
    assert manifest_data["sha256"] == res["sha256"]
    
    # Check zip contents
    with zipfile.ZipFile(zip_path, 'r') as zf:
        namelist = zf.namelist()
        assert "GHSA-1234.json" in namelist
        assert "GHSA-5678.json" not in namelist
        
        info = zf.getinfo("GHSA-1234.json")
        # Ensure timestamp is deterministic (1980-01-01)
        assert info.date_time == (1980, 1, 1, 0, 0, 0)

import gzip
import json
from pathlib import Path

import tarfile
import subprocess
import sys

from mcp_vulnerabilities.snapshot import build_snapshot, export_airgap_bundle


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

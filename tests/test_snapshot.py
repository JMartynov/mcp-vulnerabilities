import gzip
import json
from pathlib import Path
from mcp_vulnerabilities.snapshot import build_snapshot


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

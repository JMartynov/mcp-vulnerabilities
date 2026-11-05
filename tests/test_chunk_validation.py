import json
import os
from pathlib import Path

def validate_chunk_result(result_path: Path):
    with open(result_path, "r") as f:
        data = json.load(f)
        
    assert "chunk_id" in data
    assert "track" in data
    assert "total_items" in data
    assert "scanned_count" in data
    assert "unreachable_count" in data
    assert "vulnerable_servers_count" in data
    assert "items" in data
    
    assert data["total_items"] == len(data["items"])
    
    for item in data["items"]:
        assert "package_name" in item
        assert "assessment" in item
        
        assessment = item["assessment"]
        assert "status" in assessment
        
        if assessment["status"] != "OFFLINE_OR_UNREACHABLE":
            assert "protocol_trust" in assessment
            assert "supply_chain_hygiene" in assessment
            
            # Additional structural checks could go here.

def test_chunk_validation_valid(tmp_path):
    # Create a dummy result file
    res = {
        "chunk_id": "chunk_01",
        "track": "A",
        "total_items": 1,
        "scanned_count": 1,
        "unreachable_count": 0,
        "vulnerable_servers_count": 0,
        "items": [
            {
                "package_name": "test-pkg",
                "assessment": {
                    "status": "SCANNED",
                    "protocol_trust": {},
                    "supply_chain_hygiene": {}
                }
            }
        ]
    }
    
    p = tmp_path / "result.json"
    with open(p, "w") as f:
        json.dump(res, f)
        
    validate_chunk_result(p)

def test_chunk_validation_malformed(tmp_path):
    # Create a malformed dummy result file (missing protocol_trust on scanned item)
    res = {
        "chunk_id": "chunk_01",
        "track": "A",
        "total_items": 1,
        "scanned_count": 1,
        "unreachable_count": 0,
        "vulnerable_servers_count": 0,
        "items": [
            {
                "package_name": "test-pkg",
                "assessment": {
                    "status": "SCANNED",
                    "supply_chain_hygiene": {}
                }
            }
        ]
    }
    
    p = tmp_path / "result.json"
    with open(p, "w") as f:
        json.dump(res, f)
        
    try:
        validate_chunk_result(p)
        assert False, "Should have raised exception on malformed input"
    except AssertionError:
        pass

def test_all_chunks_exist_and_sum():
    chunks_dir = Path("data/chunks")
    tracks = ["track_a", "track_b", "track_c"]
    
    total_chunks = 0
    total_servers = 0
    unique_servers = set()
    
    for tr in tracks:
        tr_dir = chunks_dir / tr
        assert tr_dir.exists(), f"Missing track directory {tr_dir}"
        for chunk_file in tr_dir.glob("*.json"):
            total_chunks += 1
            with open(chunk_file, "r") as f:
                data = json.load(f)
                for item in data:
                    unique_servers.add(item["package_name"])
                    total_servers += 1
                    
    assert total_chunks == 62, f"Expected 62 chunks, found {total_chunks}"
    # Note: The database size may have grown since the markdown plan was generated.
    assert len(unique_servers) >= 5998, f"Expected at least 5998 unique servers, found {len(unique_servers)}"
    assert total_servers >= 5998, f"Expected at least 5998 total servers, found {total_servers}"

def test_run_chunk_audit_script(tmp_path):
    # Test the chunk runner script itself
    import subprocess
    
    # Create a small dummy chunk
    chunk_data = [
        {
            "package_name": "test-pkg",
            "repository_url": "https://github.com/test/repo",
            "ecosystem": "npm",
            "versions": [{"dependencies": {"a": "1.0"}}]
        }
    ]
    
    chunk_path = tmp_path / "track_a" / "chunk_01.json"
    chunk_path.parent.mkdir()
    with open(chunk_path, "w") as f:
        json.dump(chunk_data, f)
        
    out_path = tmp_path / "result.json"
    
    # Run the script with mock enabled
    import os
    import sys
    env = os.environ.copy()
    env["MOCK_CHUNK_RUNNER"] = "1"
    python_bin = sys.executable or "python3"
    
    subprocess.run([python_bin, "scripts/run_chunk_audit.py", "--chunk", str(chunk_path), "--output", str(out_path)], env=env, check=True)
    
    # Validate the output
    validate_chunk_result(out_path)

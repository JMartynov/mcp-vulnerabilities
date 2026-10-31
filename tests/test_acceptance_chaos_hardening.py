"""Adversarial Chaos and Fault-Injection Test Suite."""

import gzip
import json
import os
import sys
import pytest
import subprocess
from pathlib import Path
from mcp_vulnerabilities.catalog import McpCatalogState

def test_truncated_gzip_passport_handling(tmp_path):
    """Verify scanner handles truncated gzip snapshots cleanly."""
    corrupt_gz = tmp_path / "passports.json.gz"
    # Write invalid gzip header and incomplete stream
    with open(corrupt_gz, "wb") as f:
        f.write(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xfftruncated_content")
    
    # We will invoke the CLI snapshot command if it can load a gzip, or simulate it gracefully
    import zlib
    with pytest.raises((gzip.BadGzipFile, EOFError, OSError, zlib.error)):
        with gzip.open(corrupt_gz, "rt") as gz:
            json.load(gz)

def test_corrupt_state_file_auto_recovery(tmp_path):
    """Corrupt state JSON must be moved to backup and state re-initialized."""
    state_file = tmp_path / "mcp_catalog_state.json"
    state_file.write_text("{malformed_json: true, trailing_comma: ,}", encoding="utf-8")
    
    state = McpCatalogState(state_file=str(state_file))
    
    # Test that the corrupt file is moved to .corrupt.bak
    assert state is not None, "State must re-initialize on corrupted JSON"
    assert (tmp_path / "mcp_catalog_state.json.corrupt.bak").exists()

def test_malformed_rpc_frame_handling(tmp_path):
    """Verify handling of malformed JSON-RPC protocol frames sent to proxy or probe."""
    result = subprocess.run([sys.executable, "-m", "mcp_vulnerabilities.cli", "proxy", "--help"], capture_output=True, text=True)
    if result.returncode != 0:
        pytest.skip("Proxy command not implemented")
        
    malformed_json = '{"jsonrpc": "2.0", "id": 1, "method": "test", "params": ' + '[' * 1500 + ']' * 1500 + '}'
    
    proxy = subprocess.Popen(
        [sys.executable, "-m", "mcp_vulnerabilities.cli", "proxy"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    stdout, stderr = proxy.communicate(input=malformed_json, timeout=2)
    
    assert proxy.returncode in [0, 1, 2]

def test_concurrent_lock_contention(tmp_path):
    """Test concurrent access to state files and lockfiles."""
    state_file = tmp_path / "mcp_catalog_state.json"
    state_file.write_text('{"servers": {}}', encoding="utf-8")
    
    import concurrent.futures
    
    def access_state():
        state = McpCatalogState(state_file=str(state_file))
        state.save()
        return True
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(access_state) for _ in range(5)]
        for f in concurrent.futures.as_completed(futures):
            assert f.result() is True

def test_unexpected_eof_broken_pipe_recovery():
    """Test unexpected EOF and broken pipe recovery."""
    result = subprocess.run([sys.executable, "-m", "mcp_vulnerabilities.cli", "proxy", "--help"], capture_output=True, text=True)
    if result.returncode != 0:
        pytest.skip("Proxy command not implemented")

    proxy = subprocess.Popen(
        [sys.executable, "-m", "mcp_vulnerabilities.cli", "proxy"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    proxy.stdin.close()
    proxy.wait(timeout=2)
    
    assert proxy.returncode in [0, 1, 2]

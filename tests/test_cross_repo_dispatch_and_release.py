import pytest
import yaml
import subprocess
import os
import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List

# Fix import path for running manually
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

# Mock OsvVulnerability to avoid pydantic version issues during tests
@dataclass
class OsvVulnerabilityMock:
    id: str
    affected: list = field(default_factory=list)
    severity: list = field(default_factory=list)

def test_invariant_1a_event_binding():
    with open(".github/workflows/cross_repo_sync.yml", "r") as f:
        workflow = yaml.safe_load(f)
    
    events = workflow.get(True, workflow.get("on", {}))
    assert "repository_dispatch" in events
    assert "upstream_fingerprints_updated" in events["repository_dispatch"]["types"]

def test_invariant_1b_payload_extraction():
    with open(".github/workflows/cross_repo_sync.yml", "r") as f:
        content = f.read()
    
    assert "${{ github.event.client_payload.upstream_version }}" in content
    assert "${{ github.event.client_payload.passports_count }}" in content

def test_invariant_2_delta_detector():
    try:
        from mcp_vulnerabilities.delta_detector import DeltaDetector
    except ImportError:
        pytest.skip("mcp_vulnerabilities module not available")
        
    detector = DeltaDetector()
    
    # Case A: 0 new CVEs
    old_data = [
        OsvVulnerabilityMock(id="GHSA-1234")
    ]
    new_data_case_a = [
        OsvVulnerabilityMock(id="GHSA-1234")
    ]
    
    has_delta = detector.evaluate_deltas(old_data, new_data_case_a)
    assert has_delta is False
    
    # Case B: New CVE added
    new_data_case_b = [
        OsvVulnerabilityMock(id="GHSA-1234"),
        OsvVulnerabilityMock(id="GHSA-5678")
    ]
    has_delta = detector.evaluate_deltas(old_data, new_data_case_b)
    assert has_delta is True

def test_invariant_3a_fallback_rate_limit():
    try:
        from mcp_vulnerabilities.sync_manager import CrossRepoSyncManager
    except ImportError:
        pytest.skip("mcp_vulnerabilities module not available")
        
    import threading
    from http.server import HTTPServer, BaseHTTPRequestHandler
    
    class RateLimitHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if "releases/latest" in self.path:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'{"message": "API rate limit exceeded"}')
            elif "passports.json.gz" in self.path:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"dummy data")
            else:
                self.send_response(404)
                self.end_headers()
                
    server = HTTPServer(("127.0.0.1", 0), RateLimitHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    
    manager = CrossRepoSyncManager(
        target_path=Path("test_passports.json.gz"),
        raw_github_url=f"http://127.0.0.1:{port}/passports.json.gz"
    )
    manager.github_api_url = f"http://127.0.0.1:{port}/repos/jmartynov/mcp-fingerprints/releases/latest"
    
    result = manager.fetch_latest_passports()
    assert result is True
    assert Path("test_passports.json.gz").exists()
    
    # Cleanup
    if Path("test_passports.json.gz").exists():
        os.remove("test_passports.json.gz")
    server.shutdown()
    server.server_close()
    thread.join(timeout=1)

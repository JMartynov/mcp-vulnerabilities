import json
import threading
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest
import time
from pathlib import Path
from typing import Dict, Any

from mcp_vulnerabilities.probe.transport import (
    StdioTransport,
    HttpSseTransport,
    TransportError,
    TransportTimeoutError,
)
from mcp_vulnerabilities.probe.client import McpProbeClient
from mcp_vulnerabilities.fingerprints.matcher import FingerprintMatcher
from mcp_fingerprints.models import ServerPackageSpec, VersionFingerprint, ToolContractSignature

# Scenario 1: STDIO NOISE
def test_scenario1_stdio_noise_filtering(tmp_path):
    # Create a script that emits noise then valid json
    script_path = tmp_path / "noisy_server.py"
    script_path.write_text("""
import sys
import json

# Read requests
while True:
    line = sys.stdin.readline()
    if not line:
        break
    try:
        req = json.loads(line)
        if req.get("method") == "initialize":
            # Emit noise
            print("INFO:root:Starting server...")
            print("Debug warning 123")
            sys.stdout.flush()
            
            # Emit valid JSON response for the initialize request
            resp = {
                "jsonrpc": "2.0",
                "id": req.get("id", 1),
                "result": {
                    "serverInfo": {"name": "test-server", "version": "1.0.0"},
                    "capabilities": {}
                }
            }
            print(json.dumps(resp))
            sys.stdout.flush()
        
        elif req.get("method") == "notifications/initialized":
            pass
        elif req.get("method") == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": req.get("id", 1),
                "result": {
                    "tools": []
                }
            }
            print(json.dumps(resp))
            sys.stdout.flush()
    except Exception as e:
        pass
""")
    
    transport = StdioTransport(command=sys.executable, args=[str(script_path)])
    
    client = McpProbeClient(transport)
    client.connect_and_discover(timeout=2.0)
    
    assert client.server_info.get("name") == "test-server"
    
    # Check that closing terminates the process
    client.close()
    assert transport.process is None or transport.process.poll() is not None

# Scenario 2: SSE Transport Resilience
def test_scenario2_sse_network_failures(tmp_path):
    class FakeSSEServer(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/sse":
                self.send_response(200)
                self.send_header('Content-type', 'text/event-stream')
                self.end_headers()
                
                # Send endpoint event
                self.wfile.write(b"event: endpoint\n")
                self.wfile.write(b"data: /message\n\n")
                self.wfile.flush()
                
                # Drop connection abruptly by terminating the thread/handler
                return
                
        def log_message(self, format, *args):
            pass

    server = HTTPServer(('127.0.0.1', 0), FakeSSEServer)
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()

    transport = HttpSseTransport(url=f"http://127.0.0.1:{port}/sse")
    
    try:
        transport.start()
        # Transport should notice the connection is broken and set error or close
        # when we try to receive
        with pytest.raises(TransportError):
            transport.receive(timeout=1.0)
    finally:
        transport.stop()
        server.shutdown()
        server_thread.join()

# Scenario 3: Topological Similarity
def test_scenario3_topological_similarity(tmp_path):
    passports_file = tmp_path / "passports.json"
    
    # We create a passport with tools: T1, T2, T3
    passport_data = {
        "passports": {
            "test-pkg": {
                "package_name": "test-pkg",
                "ecosystem": "npm",
                    "purl": "pkg:npm/test-pkg",
                "repository_url": "https://github.com/test/test",
                "versions": [
                    {
                        "version": "1.0.0",
                        "toolset_canonical_hash": "hash123",
                        "tool_signatures": [
                            {"name": "tool_one", "canonical_hash": "sha256:ad45c7116c2831234a8d69a091460e0e81d1f4e05668e1bd189d064da2ca45a7", "property_keys": ["prop1", "prop2"]},
                            {"name": "tool_two", "canonical_hash": "sha256:d920f1eca37b50dd3f7a48b6776ebe245b37dcf14724bb3ce2ce0cd3e02bb95d", "property_keys": ["prop3", "prop4"]},
                            {"name": "tool_three", "canonical_hash": "sha256:8dcbd766343fa6fdc5f42091cac716fc6214c534be1eabdfcd2aa3bc5ec0f630", "property_keys": ["prop5", "prop6"]},
                        ]
                    }
                ]
            }
        }
    }
    
    with open(passports_file, "w") as f:
        json.dump(passport_data, f)
        
    matcher = FingerprintMatcher(passports_file)
    
    # Probe a server that has tool_one, tool_two, tool_three, and tool_four
    probed_tools = [
        {"name": "tool_one", "inputSchema": {"properties": {"prop1": {}, "prop2": {}}}},
        {"name": "tool_two", "inputSchema": {"properties": {"prop3": {}, "prop4": {}}}},
        {"name": "tool_three", "inputSchema": {"properties": {"prop5": {}, "prop6": {}}}},
        {"name": "tool_four", "inputSchema": {"properties": {"prop7": {}}}}, # new tool
    ]
    
    results = matcher.match_tools(probed_tools)
    
    assert len(results) > 0
    top_match = results[0]
    
    assert top_match.package_name == "test-pkg"
    assert top_match.confidence_score >= 0.75

# Scenario 3B: Vulnerability Correlation Stamping Invariant
def test_scenario3b_vulnerability_correlation(tmp_path):
    from mcp_vulnerabilities.fingerprints.correlator import VulnerabilityCorrelator
    passports_file = tmp_path / "passports2.json"
    
    passport_data = {
        "passports": {
            "test-pkg": {
                "package_name": "test-pkg",
                "ecosystem": "npm",
                "purl": "pkg:npm/test-pkg",
                "repository_url": "https://github.com/test/test",
                "versions": [
                    {
                        "version": "1.0.0",
                        "toolset_canonical_hash": "hash123",
                        "tool_signatures": [
                            {"name": "tool_one", "canonical_hash": "sha256:ad45c7116c2831234a8d69a091460e0e81d1f4e05668e1bd189d064da2ca45a7", "property_keys": ["prop1", "prop2"]},
                        ]
                    }
                ]
            }
        }
    }
    
    with open(passports_file, "w") as f:
        json.dump(passport_data, f)
        
    matcher = FingerprintMatcher(passports_file)
    
    class FakeMatcher:
        def __init__(self):
            self._package_index = {}
        def match_package(self, package: str, version: str):
            # No vulnerabilities for now, just verifying the timeline gets built
            return []
            
    correlator = VulnerabilityCorrelator(matcher=FakeMatcher(), passports=matcher.packages)
    timeline = correlator.correlate_package("test-pkg")
    assert len(timeline.timeline) == 1
    assert timeline.timeline[0].version == "1.0.0"

# Scenario 1B: Timeout & Process Teardown Invariant
def test_scenario1_timeout_teardown(tmp_path):
    # Create a script that blocks forever and never emits valid JSON
    script_path = tmp_path / "blocking_server.py"
    script_path.write_text("""
import sys
import time

# Block forever
time.sleep(100)
""")
    
    transport = StdioTransport(command=sys.executable, args=[str(script_path)])
    client = McpProbeClient(transport)
    
    # Should timeout because server is unresponsive
    with pytest.raises(TransportTimeoutError):
        client.connect_and_discover(timeout=0.5)
        
    # The timeout exception should trigger `self.stop()` internally
    # Wait a bit for teardown
    time.sleep(0.5)
    
    # Process must be gone
    assert transport.process is None or transport.process.poll() is not None


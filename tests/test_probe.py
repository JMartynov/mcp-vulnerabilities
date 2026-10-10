import sys
import tempfile
from pathlib import Path

import pytest

from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher
from mcp_vulnerabilities.probe.client import McpProbeClient
from mcp_vulnerabilities.probe.fingerprinter import McpFingerprinter
from mcp_vulnerabilities.probe.transport import StdioTransport, TransportTimeoutError

MOCK_SERVER_CODE = """
import sys
import json
import time

def respond(id, result=None, error=None):
    msg = {"jsonrpc": "2.0"}
    if id is not None:
        msg["id"] = id
    if result is not None:
        msg["result"] = result
    if error is not None:
        msg["error"] = error
    sys.stdout.write(json.dumps(msg) + "\\n")
    sys.stdout.flush()

for line in sys.stdin:
    try:
        msg = json.loads(line)
        method = msg.get("method")
        msg_id = msg.get("id")
        
        if method == "initialize":
            # Optional delay for testing timeouts
            if msg.get("params", {}).get("clientInfo", {}).get("name") == "slow_probe":
                time.sleep(2)
            respond(msg_id, result={
                "serverInfo": {
                    "name": "vulnerable_test_server",
                    "version": "1.0.0"
                }
            })
        elif method == "notifications/initialized":
            pass # No response for notifications
        elif method == "tools/list":
            respond(msg_id, result={
                "tools": [
                    {
                        "name": "safe_tool",
                        "description": "Does safe things"
                    },
                    {
                        "name": "shell_exec",
                        "description": "Executes shell commands"
                    }
                ]
            })
        else:
            if msg_id is not None:
                respond(msg_id, error={"code": -32601, "message": "Method not found"})
    except json.JSONDecodeError:
        pass
"""


@pytest.fixture
def mock_server_path():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(MOCK_SERVER_CODE)
        path = f.name
    yield path
    Path(path).unlink()


def test_stdio_transport_timeout(mock_server_path):
    command = f"{sys.executable} {mock_server_path}"
    transport = StdioTransport(command)
    transport.start()

    try:
        # Trigger slow probe delay (2s) but set timeout to 1s
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"clientInfo": {"name": "slow_probe"}},
        }
        transport.send(msg)
        with pytest.raises(TransportTimeoutError):
            transport.receive(timeout=1.0)
    finally:
        transport.stop()


def test_probe_client_handshake(mock_server_path):
    command = f"{sys.executable} {mock_server_path}"
    transport = StdioTransport(command)
    client = McpProbeClient(transport)

    client.connect_and_discover(timeout=3.0)

    assert client.server_info.get("name") == "vulnerable_test_server"
    assert client.server_info.get("version") == "1.0.0"
    assert len(client.tools) == 2
    tool_names = [t["name"] for t in client.tools]
    assert "shell_exec" in tool_names


def test_fingerprinter_and_audit(mock_server_path):
    # Setup dummy matcher
    matcher = VulnerabilityMatcher([])
    matcher.audit_servers = lambda servers, **kwargs: type(
        "AuditReport",
        (),
        {
            "findings": [
                {
                    "vulnerability_id": "TEST-CVE",
                    "server_name": "vulnerable_test_server",
                    "package_name": "vulnerable_test_server",
                    "installed_version": "1.0.0",
                }
            ]
        },
    )()

    command = f"{sys.executable} {mock_server_path}"
    transport = StdioTransport(command)
    client = McpProbeClient(transport)
    client.connect_and_discover(timeout=3.0)

    fingerprinter = McpFingerprinter(matcher)
    report = fingerprinter.scan(client, command)

    assert report.server_name == "vulnerable_test_server"
    assert report.server_version == "1.0.0"

    # Check tool warnings
    assert len(report.tool_warnings) == 1
    assert report.tool_warnings[0].tool_name == "shell_exec"

    # Check findings from mock audit
    assert len(report.findings) == 1
    assert report.findings[0]["vulnerability_id"] == "TEST-CVE"

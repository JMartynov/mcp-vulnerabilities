import pytest
import sys
import tempfile
import json
from pathlib import Path
from mcp_vulnerabilities.probe.transport import StdioTransport
from mcp_vulnerabilities.probe.client import McpProbeClient

MOCK_STDIO_CODE = """
import sys
import json

for line in sys.stdin:
    try:
        msg = json.loads(line)
        method = msg.get("method")
        msg_id = msg.get("id")
        
        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "serverInfo": {"name": "test_stdio", "version": "1.0"},
                    "capabilities": {"tools": {}}
                }
            }
            sys.stdout.write(json.dumps(resp) + "\\n")
            sys.stdout.flush()
        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [{"name": "stdio_tool"}]
                }
            }
            sys.stdout.write(json.dumps(resp) + "\\n")
            sys.stdout.flush()
    except json.JSONDecodeError:
        pass
"""


def test_live_stdio_real_subprocess():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(MOCK_STDIO_CODE)
        path = f.name

    try:
        command = f"{sys.executable} {path}"
        transport = StdioTransport(command)
        client = McpProbeClient(transport)

        client.connect_and_discover(timeout=3.0)

        assert client.server_info["name"] == "test_stdio"
        assert len(client.tools) == 1
        assert client.tools[0]["name"] == "stdio_tool"
    finally:
        Path(path).unlink()

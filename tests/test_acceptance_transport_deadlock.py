import sys
import tempfile
import json
import time
from pathlib import Path
from mcp_vulnerabilities.probe.transport import StdioTransport
from mcp_vulnerabilities.probe.client import McpProbeClient

MOCK_STDIO_DEADLOCK_CODE = """
import sys
import json
import time

# Write 256KB to stderr
sys.stderr.write("A" * 1024 * 256 + "\\n")
sys.stderr.flush()

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
            break
    except json.JSONDecodeError:
        pass
"""

def test_live_stdio_unmocked_stderr_flood_deadlock():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(MOCK_STDIO_DEADLOCK_CODE)
        path = f.name

    try:
        transport = StdioTransport(sys.executable, args=[path])
        with McpProbeClient(transport) as client:
            # Should complete within the timeout without deadlocking
            client.connect_and_discover(timeout=5.0)

            assert client.server_info["name"] == "test_stdio"
            assert len(client.tools) == 1
            assert client.tools[0]["name"] == "stdio_tool"
            
            # Verify stderr lines are captured (the last line is A*256KB)
            assert len(transport.last_stderr_lines) > 0
            assert "A" * 100 in transport.last_stderr_lines[-1]
    finally:
        Path(path).unlink()

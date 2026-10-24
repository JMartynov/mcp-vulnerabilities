import subprocess
import json
import os
import sys
import shutil
from pathlib import Path

def test_acceptance_cyclonedx_audit():
    config_path = Path("tests/fixtures/claude_desktop_config_sbom.json")
    
    # Run the audit command with cyclonedx format
    cmd =  [
        sys.executable, "-m", "mcp_vulnerabilities.cli", "audit", 
        "--config", str(config_path), 
        "--format", "cyclonedx"
    ]
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "src"}
    )
    
    assert result.returncode in (0, 1), f"Unexpected failure: {result.stderr}"
    
    try:
        sbom = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"Failed to decode JSON from stdout: {result.stdout}")
        raise
        
    assert sbom.get("bomFormat") == "CycloneDX"
    assert sbom.get("specVersion") == "1.6"
    assert "serialNumber" in sbom
    assert "version" in sbom
    assert "metadata" in sbom
    assert "components" in sbom
    
    components = sbom["components"]
    names = [c.get("name") for c in components]
    
    assert "@modelcontextprotocol/server-filesystem" in names
    assert "@modelcontextprotocol/server-github" in names
    assert "@modelcontextprotocol/server-postgres" in names

def test_acceptance_cyclonedx_probe():
    # Use a simple python snippet to act as a mock MCP stdio server
    # We will just assert that probe outputs valid cycloneDX JSON 
    # and has the necessary fields.
    
    # 1. Prepare a mock server script
    mock_server_path = Path("tests/fixtures/sbom_mock_server.py")
    mock_server_path.write_text("""
import sys
import json

def handle_init(msg_id):
    resp = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "mock-sbom-server", "version": "1.0.0"}
        }
    }
    sys.stdout.write(json.dumps(resp) + '\\n')
    sys.stdout.flush()

def handle_tools(msg_id):
    resp = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "tools": [
                {
                    "name": "mock_tool",
                    "description": "Mock tool for SBOM testing",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"arg1": {"type": "string"}},
                        "required": ["arg1"]
                    }
                }
            ]
        }
    }
    sys.stdout.write(json.dumps(resp) + '\\n')
    sys.stdout.flush()

def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        if not line.strip(): 
            continue
        try:
            msg = json.loads(line)
            if msg.get("method") == "initialize":
                handle_init(msg.get("id"))
            elif msg.get("method") == "notifications/initialized":
                pass
            elif msg.get("method") == "tools/list":
                handle_tools(msg.get("id"))
            elif msg.get("method") == "prompts/list":
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"prompts": []}}) + '\\n')
                sys.stdout.flush()
            elif msg.get("method") == "resources/list":
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"resources": []}}) + '\\n')
                sys.stdout.flush()
        except Exception as e:
            pass

if __name__ == '__main__':
    main()
    """)

    cmd =  [
        sys.executable, "-m", "mcp_vulnerabilities.cli", "probe", 
        "--command", f"{sys.executable} {mock_server_path}", 
        "--format", "cyclonedx"
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "src"}
    )
    
    # Probe might return 0 or 1 depending on threats, but output should be valid JSON
    assert result.returncode in (0, 1), f"Unexpected failure: {result.stderr}"
    
    try:
        sbom = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"Failed to decode JSON from stdout: {result.stdout}")
        print(f"Stderr: {result.stderr}")
        raise
        
    assert sbom.get("bomFormat") == "CycloneDX"
    assert sbom.get("specVersion") == "1.6"
    assert "services" in sbom
    
    services = sbom["services"]
    assert len(services) == 1
    
    mock_service = services[0]
    assert mock_service["name"] == "mock-sbom-server"
    assert mock_service["version"] == "1.0.0"
    assert "endpoints" in mock_service
    assert len(mock_service["endpoints"]) == 1
    assert mock_service["endpoints"][0] == "mcp://mock-sbom-server/tools/mock_tool"
    
    components = sbom.get("components", [])
    tool_components = [c for c in components if c.get("name") == "mock_tool"]
    assert len(tool_components) == 1
    tool_comp = tool_components[0]
    assert "hashes" in tool_comp
    
    assert "dependencies" in sbom
    

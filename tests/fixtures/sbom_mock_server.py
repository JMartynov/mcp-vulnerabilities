
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
    sys.stdout.write(json.dumps(resp) + '\n')
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
    sys.stdout.write(json.dumps(resp) + '\n')
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
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"prompts": []}}) + '\n')
                sys.stdout.flush()
            elif msg.get("method") == "resources/list":
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"resources": []}}) + '\n')
                sys.stdout.flush()
        except Exception as e:
            pass

if __name__ == '__main__':
    main()
    
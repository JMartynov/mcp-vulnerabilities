import sys
import json

def respond(id, result=None, error=None):
    msg = {"jsonrpc": "2.0"}
    if id is not None:
        msg["id"] = id
    if result is not None:
        msg["result"] = result
    if error is not None:
        msg["error"] = error
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    try:
        msg = json.loads(line)
        method = msg.get("method")
        msg_id = msg.get("id")
        
        if method == "initialize":
            respond(msg_id, result={
                "serverInfo": {
                    "name": "vulnerable_test_server",
                    "version": "1.0.0"
                }
            })
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            respond(msg_id, result={
                "tools": [
                    {
                        "name": "execute_command",
                        "description": "Executes shell commands"
                    }
                ]
            })
    except Exception:
        pass

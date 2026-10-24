import json
import subprocess
import sys
import threading
from typing import Any, IO
from .policy import ProxyPolicyEngine, PolicyDecision, AuditEvent
import time

class McpStdioProxy:
    def __init__(
        self,
        policy_engine: ProxyPolicyEngine,
        mode: str = "block",
        audit_log_path: str | None = None,
        strip_shadow_tools: bool = True
    ):
        self.policy_engine = policy_engine
        self.mode = mode
        self.audit_log_path = audit_log_path
        self.strip_shadow_tools = strip_shadow_tools
        self.pending_requests = {} # id -> method

    def log_audit_event(self, event: AuditEvent):
        if self.audit_log_path:
            with open(self.audit_log_path, "a") as f:
                f.write(json.dumps(event.__dict__) + "\n")
        sys.stderr.write(f"[{event.severity}] {event.event_type}: {event.details}\n")

    def process_client_line(self, line: str) -> tuple[str | None, str | None]:
        # Returns (to_server, to_client)
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return line, None

        msg_id = msg.get("id")
        method = msg.get("method")

        if msg_id is not None and method:
            self.pending_requests[msg_id] = method

        decision = self.policy_engine.evaluate_request(msg)
        if not decision.allowed:
            event = AuditEvent("POLICY_VIOLATION", decision.severity, decision.reason, {"request": msg}, "Blocked" if self.mode == "block" else "Logged")
            self.log_audit_event(event)

            if self.mode == "block":
                if msg_id is not None:
                    error_resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32001,
                            "message": f"Blocked by MCP Security Proxy: {decision.reason}",
                            "data": {"rule_id": decision.rule_id}
                        }
                    }
                    return None, json.dumps(error_resp)
                return None, None

        return json.dumps(msg), None

    def process_server_line(self, line: str) -> str | None:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return line

        msg_id = msg.get("id")
        request_method = None
        if msg_id is not None:
            # We must pop the request ID from pending_requests to prevent memory leaks
            request_method = self.pending_requests.pop(msg_id, None)

        if "result" in msg or "error" in msg:
            new_msg, events = self.policy_engine.inspect_response(msg, request_method)
            for event in events:
                self.log_audit_event(event)
            
            if request_method == "tools/list" and not self.strip_shadow_tools:
                # Do not strip if disabled, use the original message
                return json.dumps(msg)
            
            return json.dumps(new_msg)

        return line

    def run_stdio(self, command: list[str], stdin: IO[str] = sys.stdin, stdout: IO[str] = sys.stdout, stderr: IO[str] = sys.stderr) -> int:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=True,
            bufsize=1
        )

        def server_reader():
            for line in proc.stdout:
                processed = self.process_server_line(line.strip())
                if processed is not None:
                    stdout.write(processed + "\n")
                    stdout.flush()
        
        t = threading.Thread(target=server_reader, daemon=True)
        t.start()

        try:
            for line in stdin:
                to_server, to_client = self.process_client_line(line.strip())
                if to_server:
                    proc.stdin.write(to_server + "\n")
                    proc.stdin.flush()
                if to_client:
                    stdout.write(to_client + "\n")
                    stdout.flush()
                    
            # Wait for thread to finish reading before tearing down
            time.sleep(1)
        except EOFError:
            pass
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            
        return proc.returncode

import json
import subprocess
import sys
import threading
import shlex
from typing import IO, Any
from .policy import ProxyPolicyEngine, AuditEvent
import time
from mcp_vulnerabilities.probe.sandbox_prober import DockerSandboxDriver, RestrictedSubprocessDriver, CanarySecretGuard

class McpStdioProxy:
    def __init__(
        self,
        policy_engine: ProxyPolicyEngine,
        mode: str = "block",
        audit_log_path: str | None = None,
        strip_shadow_tools: bool = True,
        sandbox: str = "none",
        canary_detection: bool = False
    ):
        self.policy_engine = policy_engine
        self.mode = mode
        self.audit_log_path = audit_log_path
        self.strip_shadow_tools = strip_shadow_tools
        self.pending_requests: dict[Any, str] = {} # id -> method
        self.sandbox = sandbox
        self.canary_detection = canary_detection

        self.driver: DockerSandboxDriver | RestrictedSubprocessDriver | None = None
        if self.sandbox == "docker":
            self.driver = DockerSandboxDriver(allow_outbound=False)
        elif self.sandbox == "subprocess":
            self.driver = RestrictedSubprocessDriver()


        self.canary_guard = None
        if self.canary_detection:
            if self.driver:
                self.canary_guard = self.driver.guard
            else:
                import tempfile
                self._temp_dir = tempfile.TemporaryDirectory()
                self.canary_guard = CanarySecretGuard(self._temp_dir.name)


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

        # Scan outbound payload for canary leaks if canary detection is enabled
        if self.canary_guard and method == "tools/call":
            payload_str = json.dumps(msg.get("params", {}))
            leaks = self.canary_guard.analyze_payload(payload_str)
            if leaks:
                event = AuditEvent("CANARY_LEAK_DETECTED", "CRITICAL", f"Canary leak detected in tool call: {leaks}", {"leaks": leaks, "request": msg}, "Blocked execution")
                self.log_audit_event(event)
                # Force block on Canary leaks regardless of mode
                if msg_id is not None:
                    error_resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32001,
                            "message": "Blocked by MCP Security Proxy: Canary leak detected in tool call payload",
                            "data": {"rule_id": "CANARY_LEAK_DETECTED"}
                        }
                    }
                    return None, json.dumps(error_resp)
                return None, None

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
        env = None
        cmd = command
        if self.driver:
            cmd_str = shlex.join(command)
            wrapped_cmd_str = self.driver.wrap_command(cmd_str, is_http=False)
            cmd = shlex.split(wrapped_cmd_str)
            env = self.driver.get_env()

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=True,
            bufsize=1,
            env=env
        )

        def server_reader():
            try:
                for line in proc.stdout:
                    processed = self.process_server_line(line.strip())
                    if processed is not None:
                        try:
                            stdout.write(processed + "\n")
                            stdout.flush()
                        except (BrokenPipeError, IOError):
                            break
            except Exception:
                pass

        t = threading.Thread(target=server_reader, daemon=True)
        t.start()

        try:
            for line in stdin:
                to_server, to_client = self.process_client_line(line.strip())
                if to_server and proc.stdin:
                    try:
                        proc.stdin.write(to_server + "\n")
                        proc.stdin.flush()
                    except (BrokenPipeError, IOError):
                        break
                if to_client:
                    try:
                        stdout.write(to_client + "\n")
                        stdout.flush()
                    except (BrokenPipeError, IOError):
                        break

            # Wait briefly for thread to finish reading before tearing down
            time.sleep(0.5)
        except (EOFError, KeyboardInterrupt):
            pass
        finally:
            if proc.stdin and not proc.stdin.closed:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except (subprocess.TimeoutExpired, ProcessLookupError, Exception):
                try:
                    proc.kill()
                except Exception:
                    pass

            if self.driver:
                self.driver.cleanup()
            if hasattr(self, '_temp_dir'):
                self._temp_dir.cleanup()

        return proc.returncode

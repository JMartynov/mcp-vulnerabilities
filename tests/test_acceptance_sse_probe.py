import pytest
import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

from mcp_vulnerabilities.probe.transport import HttpSseTransport, TransportAuthError
from mcp_vulnerabilities.probe.client import McpProbeClient


class MockLiveSseServer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass  # Silence logging for tests

    def do_GET(self):
        auth_header = self.headers.get("Authorization")
        if getattr(self.server, "require_auth", None):
            if auth_header != f"Bearer {self.server.require_auth}":
                self.send_response(401)
                self.end_headers()
                return

        if self.path == "/sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            self.wfile.write(b"event: endpoint\n")
            self.wfile.write(b"data: /message\n\n")
            self.wfile.flush()

            self.server.sse_connected.set()

            try:
                while getattr(self.server, "running", True):
                    # check for messages to send
                    if self.server.messages_to_send:
                        msg = self.server.messages_to_send.pop(0)
                        encoded = json.dumps(msg)
                        self.wfile.write(b"event: message\n")
                        self.wfile.write(f"data: {encoded}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    time.sleep(0.01)
            except Exception:
                pass

    def do_POST(self):
        auth_header = self.headers.get("Authorization")
        if getattr(self.server, "require_auth", None):
            if auth_header != f"Bearer {self.server.require_auth}":
                self.send_response(401)
                self.end_headers()
                return

        if self.path == "/message":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            msg = json.loads(post_data)

            # Send OK to POST
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")
            self.wfile.flush()

            # Process JSON-RPC request and queue response for SSE thread to pick up
            req_id = msg.get("id")
            method = msg.get("method")

            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "serverInfo": {"name": "live_test_server", "version": "1.2.3"},
                        "capabilities": getattr(
                            self.server, "capabilities", {"tools": {}}
                        ),
                        "instructions": "Be helpful.",
                    },
                }
                self.server.messages_to_send.append(resp)
            elif method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [{"name": "test_tool", "description": "a tool"}]
                    },
                }
                self.server.messages_to_send.append(resp)
            elif method == "prompts/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "prompts": [{"name": "test_prompt", "description": "a prompt"}]
                    },
                }
                self.server.messages_to_send.append(resp)
            elif method == "resources/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "resources": [{"uri": "file:///test", "name": "test_resource"}]
                    },
                }
                self.server.messages_to_send.append(resp)
            elif method == "notifications/initialized":
                pass  # no response expected


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


@pytest.fixture
def live_server():
    server = ThreadingHTTPServer(("localhost", 0), MockLiveSseServer)
    server.running = True
    server.sse_connected = threading.Event()
    server.messages_to_send = []

    port = server.server_address[1]

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    yield server, f"http://localhost:{port}"

    server.running = False
    server.shutdown()
    server.server_close()
    t.join(timeout=1.0)


def test_live_sse_transport_handshake(live_server):
    server, base_url = live_server
    server.capabilities = {"tools": {}}

    transport = HttpSseTransport(f"{base_url}/sse")
    client = McpProbeClient(transport)

    client.connect_and_discover(timeout=3.0)

    assert client.server_info["name"] == "live_test_server"
    assert client.server_info["version"] == "1.2.3"
    assert len(client.tools) == 1
    assert client.tools[0]["name"] == "test_tool"


def test_live_authenticated_sse_probe(live_server):
    server, base_url = live_server
    server.require_auth = "secret-token-12345"
    server.capabilities = {"tools": {}}

    # Missing auth
    transport = HttpSseTransport(f"{base_url}/sse")
    with pytest.raises(TransportAuthError):
        transport.start()

    # Valid auth
    transport = HttpSseTransport(
        f"{base_url}/sse", headers={"Authorization": "Bearer secret-token-12345"}
    )
    client = McpProbeClient(transport)
    client.connect_and_discover(timeout=3.0)

    assert client.server_info["name"] == "live_test_server"
    assert len(client.tools) == 1


def test_live_full_surface_prompts_and_resources(live_server):
    server, base_url = live_server
    server.capabilities = {"tools": {}, "prompts": {}, "resources": {}}

    transport = HttpSseTransport(f"{base_url}/sse")
    client = McpProbeClient(transport)
    client.connect_and_discover(timeout=3.0, surfaces={"tools", "prompts", "resources"})

    assert client.surface.instructions == "Be helpful."
    assert len(client.surface.tools) == 1
    assert client.surface.tools[0]["name"] == "test_tool"
    assert len(client.surface.prompts) == 1
    assert client.surface.prompts[0]["name"] == "test_prompt"
    assert len(client.surface.resources) == 1
    assert client.surface.resources[0]["uri"] == "file:///test"

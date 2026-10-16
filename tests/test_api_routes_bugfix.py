import json
from unittest.mock import MagicMock

from mcp_vulnerabilities.api.routes import handle_identify, handle_probe, handle_scan_config


class DummyHandler:
    def __init__(self, body_dict=None, raw_body=None):
        if raw_body is not None:
            data = raw_body
        elif body_dict is not None:
            data = json.dumps(body_dict).encode("utf-8")
        else:
            data = b""

        self.headers = {"Content-Length": str(len(data))}
        import io
        self.rfile = io.BytesIO(data)


class DummyServer:
    def __init__(self):
        self.vulnerability_matcher = MagicMock()
        self.fingerprint_matcher = MagicMock()
        self.allow_remote_commands = False


def test_scan_config_severity_threshold_passed():
    server = DummyServer()
    mock_report = MagicMock()
    mock_report.findings = []
    server.vulnerability_matcher.audit_servers.return_value = mock_report
    server.fingerprint_matcher.match_tools.return_value = []

    config = {
        "mcpServers": {
            "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}
        }
    }
    payload = {
        "config": config,
        "detect_collisions": False,
        "severity_threshold": "CRITICAL"
    }

    handler = DummyHandler(body_dict=payload)
    status_code, headers, data = handle_scan_config(handler, server)

    assert status_code == 200
    assert data["servers_audited"] == 1
    server.vulnerability_matcher.audit_servers.assert_called_once()
    _, kwargs = server.vulnerability_matcher.audit_servers.call_args
    assert kwargs.get("severity_threshold") == "CRITICAL"


def test_scan_config_default_severity_threshold():
    server = DummyServer()
    mock_report = MagicMock()
    mock_report.findings = []
    server.vulnerability_matcher.audit_servers.return_value = mock_report
    server.fingerprint_matcher.match_tools.return_value = []

    config = {
        "mcpServers": {
            "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}
        }
    }
    payload = {
        "config": config,
        "detect_collisions": False,
    }

    handler = DummyHandler(body_dict=payload)
    status_code, headers, data = handle_scan_config(handler, server)

    assert status_code == 200
    server.vulnerability_matcher.audit_servers.assert_called_once()
    _, kwargs = server.vulnerability_matcher.audit_servers.call_args
    assert kwargs.get("severity_threshold") is None


def test_scan_config_invalid_body():
    server = DummyServer()
    handler = DummyHandler(raw_body=b"not json")
    status_code, headers, data = handle_scan_config(handler, server)
    assert status_code == 400
    assert data["error"]["code"] == "BAD_REQUEST"


def test_scan_config_missing_config():
    server = DummyServer()
    handler = DummyHandler(body_dict={"detect_collisions": True})
    status_code, headers, data = handle_scan_config(handler, server)
    assert status_code == 400
    assert "Missing config object" in data["error"]["message"]


def test_handle_probe_invalid_and_empty_args():
    server = DummyServer()

    # Empty payload
    handler = DummyHandler(body_dict={})
    status, _, data = handle_probe(handler, server)
    assert status == 400
    assert data["error"]["code"] == "BAD_REQUEST"

    # Invalid JSON
    handler = DummyHandler(raw_body=b"{invalid")
    status, _, data = handle_probe(handler, server)
    assert status == 400
    assert data["error"]["code"] == "BAD_REQUEST"


def test_handle_identify_invalid_inputs():
    server = DummyServer()

    # Empty payload
    handler = DummyHandler(body_dict={})
    status, _, data = handle_identify(handler, server)
    assert status == 400
    assert data["error"]["code"] == "BAD_REQUEST"

    # Server without fingerprint matcher
    server_no_fp = DummyServer()
    server_no_fp.fingerprint_matcher = None
    handler = DummyHandler(body_dict={"tools": []})
    status, _, data = handle_identify(handler, server_no_fp)
    assert status == 500
    assert data["error"]["code"] == "INTERNAL_ERROR"

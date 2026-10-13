import pytest
import json
import threading
import time
from unittest.mock import MagicMock
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.error import HTTPError

from mcp_vulnerabilities.probe.transport import (
    HttpSseTransport,
    TransportAuthError,
    TransportTimeoutError,
)


def test_http_sse_transport_initialization():
    transport = HttpSseTransport(
        "http://localhost:8080/sse",
        headers={"Custom": "Test"},
        timeout=10.0,
        insecure=True,
    )
    assert transport.url == "http://localhost:8080/sse"
    assert transport.headers["Custom"] == "Test"
    assert transport.timeout == 10.0
    assert transport.insecure is True


def test_http_sse_transport_ssl_context():
    transport_secure = HttpSseTransport("https://localhost:8080/sse", insecure=False)
    ctx_secure = transport_secure._get_ssl_context()
    assert ctx_secure.check_hostname is True

    transport_insecure = HttpSseTransport("https://localhost:8080/sse", insecure=True)
    ctx_insecure = transport_insecure._get_ssl_context()
    assert ctx_insecure.check_hostname is False

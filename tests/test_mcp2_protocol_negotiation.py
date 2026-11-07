
import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from mcp_vulnerabilities.probe.client import McpProbeClient
from mcp_vulnerabilities.probe.transport import BaseTransport
from mcp_vulnerabilities.probe.network_scanner import NetworkMCPScanner
from mcp_vulnerabilities.fingerprints.resolver import FingerprintVersionResolver
from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer
import sys

# Mock httpx since it might not be installed but is imported locally in the function
sys.modules['httpx'] = MagicMock()

class MockTransport(BaseTransport):
    def __init__(self, responses):
        self.responses = responses
        self.sent = []
        self.started = False
        
    def start(self):
        self.started = True
        
    def stop(self):
        self.started = False
        
    def send(self, message):
        self.sent.append(message)
        
    def receive(self, timeout=None):
        if self.responses:
            return self.responses.pop(0)
        return {}


def test_probe_client_mcp2_success():
    """Test successful MCP 2.0 negotiation via server/discover."""
    responses = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2026-07-28",
                "serverInfo": {"name": "test-server", "version": "2.0.0"},
                "capabilities": {"tools": {}}
            }
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"tools": []}
        }
    ]
    transport = MockTransport(responses)
    client = McpProbeClient(transport)
    
    client.connect_and_discover(surfaces={"tools"})
    
    assert len(transport.sent) == 2
    assert transport.sent[0]["method"] == "server/discover"
    assert transport.sent[1]["method"] == "tools/list"
    assert client.surface.protocol_version == "2026-07-28"
    assert client.server_info["version"] == "2.0.0"


def test_probe_client_legacy_fallback():
    """Test fallback to initialize on Method Not Found (-32601)."""
    responses = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32601, "message": "Method not found"}
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "serverInfo": {"name": "legacy-server", "version": "1.0.0"},
                "capabilities": {"tools": {}}
            }
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"tools": []}
        }
    ]
    transport = MockTransport(responses)
    client = McpProbeClient(transport)
    
    client.connect_and_discover(surfaces={"tools"})
    
    assert len(transport.sent) == 4
    assert transport.sent[0]["method"] == "server/discover"
    assert transport.sent[1]["method"] == "initialize"
    assert transport.sent[2]["method"] == "notifications/initialized"
    assert transport.sent[3]["method"] == "tools/list"
    assert client.surface.protocol_version == "2024-11-05"
    assert client.server_info["version"] == "1.0.0"


async def _test_network_scanner_mcp2_success_async():
    """Test network scanner detecting MCP 2.0."""
    scanner = NetworkMCPScanner()
    
    mock_post = AsyncMock()
    resp1 = MagicMock()
    resp1.status_code = 200
    resp1.json.return_value = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2026-07-28",
            "capabilities": {"tools": {}}
        }
    }
    
    resp2 = MagicMock()
    resp2.status_code = 200
    resp2.json.return_value = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"tools": [{"name": "test-tool"}]}
    }
    mock_post.side_effect = [resp1, resp2]
    
    # We patch the instance that the network_scanner instantiates inside the method
    mock_client = AsyncMock()
    mock_client.post = mock_post
    
    mock_client_ctx = AsyncMock()
    mock_client_ctx.__aenter__.return_value = mock_client
    
    with patch.dict("sys.modules", {'httpx': MagicMock()}), \
         patch("httpx.AsyncClient", return_value=mock_client_ctx):
        result = await scanner.probe_endpoint("127.0.0.1", 3000, "/mcp")
        
        assert result["reachable"] is True
        assert result["mcp_handshake"] is True
        assert result["protocolVersion"] == "2026-07-28"
        assert len(result["tools"]) == 1
        
        # Check that server/discover was called
        call_args = mock_post.call_args_list[0]
        assert call_args[1]["json"]["method"] == "server/discover"
        assert call_args[1]["headers"]["MCP-Protocol-Version"] == "2026-07-28"


async def _test_network_scanner_legacy_fallback_async():
    """Test network scanner falling back to legacy initialize."""
    scanner = NetworkMCPScanner()
    
    mock_post = AsyncMock()
    resp1 = MagicMock()
    resp1.status_code = 200
    resp1.json.return_value = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32601, "message": "Method not found"}
    }
    resp2 = MagicMock()
    resp2.status_code = 200
    resp2.json.return_value = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "capabilities": {"tools": {}}
        }
    }
    resp3 = MagicMock()
    resp3.status_code = 200
    resp3.json.return_value = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"tools": [{"name": "legacy-tool"}]}
    }
    mock_post.side_effect = [resp1, resp2, resp3]
    
    mock_client = AsyncMock()
    mock_client.post = mock_post
    
    mock_client_ctx = AsyncMock()
    mock_client_ctx.__aenter__.return_value = mock_client
    
    with patch.dict("sys.modules", {'httpx': MagicMock()}), \
         patch("httpx.AsyncClient", return_value=mock_client_ctx):
        result = await scanner.probe_endpoint("127.0.0.1", 3000, "/mcp")
        
        assert result["reachable"] is True
        assert result["mcp_handshake"] is True
        assert result["protocolVersion"] == "2024-11-05"
        assert len(result["tools"]) == 1
        
        # Check calls: server/discover -> initialize -> tools/list
        assert mock_post.call_count >= 3
        assert mock_post.call_args_list[0][1]["json"]["method"] == "server/discover"
        assert mock_post.call_args_list[1][1]["json"]["method"] == "initialize"
        assert mock_post.call_args_list[2][1]["json"]["method"] == "tools/list"

def test_network_scanner_mcp2_success():
    asyncio.run(_test_network_scanner_mcp2_success_async())

def test_network_scanner_legacy_fallback():
    asyncio.run(_test_network_scanner_legacy_fallback_async())

def test_resolver_stdio_mcp2_success():
    """Test resolver handshaking with MCP 2.0 stdio."""
    resolver = FingerprintVersionResolver()
    server = DiscoveredClientServer(server_name="test", package_name="test", version="unpinned", ecosystem="npm", command="test-cmd", args=["arg1"])
    
    mock_process = MagicMock()
    mock_process.stdout.readline.return_value = '{"jsonrpc": "2.0", "result": {"protocolVersion": "2026-07-28", "serverInfo": {"version": "2.0.1"}}}'
    
    with patch("subprocess.Popen", return_value=mock_process), \
         patch("select.select", return_value=([mock_process.stdout], [], [])):
        
        version, source = resolver._resolve_uncached(server)
        
        assert version == "2.0.1"
        assert source == "handshake"
        
        # Check that server/discover was sent
        written_data = mock_process.stdin.write.call_args_list[0][0][0]
        assert "server/discover" in written_data


def test_resolver_stdio_legacy_fallback():
    """Test resolver handshaking fallback for legacy stdio."""
    resolver = FingerprintVersionResolver()
    server = DiscoveredClientServer(server_name="test", package_name="test", version="unpinned", ecosystem="npm", command="test-cmd", args=["arg1"])
    
    mock_process = MagicMock()
    mock_process.stdout.readline.side_effect = [
        '{"jsonrpc": "2.0", "error": {"code": -32601}}',
        '{"jsonrpc": "2.0", "result": {"serverInfo": {"version": "1.0.5"}}}'
    ]
    
    with patch("subprocess.Popen", return_value=mock_process), \
         patch("select.select", return_value=([mock_process.stdout], [], [])):
        
        version, source = resolver._resolve_uncached(server)
        
        assert version == "1.0.5"
        assert source == "handshake"
        
        # Check that both server/discover and initialize were sent
        assert mock_process.stdin.write.call_count == 2
        assert "server/discover" in mock_process.stdin.write.call_args_list[0][0][0]
        assert "initialize" in mock_process.stdin.write.call_args_list[1][0][0]

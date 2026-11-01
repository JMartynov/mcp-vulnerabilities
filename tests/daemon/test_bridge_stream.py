import asyncio
import json
import base64
import hashlib
import os
import pytest
import aiohttp
import struct
import websockets
from mcp_vulnerabilities.daemon.bridge import BridgeDaemon

import pytest_asyncio

@pytest_asyncio.fixture(loop_scope="function")
async def bridge_daemon(unused_tcp_port):
    daemon = BridgeDaemon(port=unused_tcp_port, simulate=True)
    await daemon.start()
    yield daemon
    await daemon.stop()

@pytest.mark.asyncio
async def test_loopback_binding_invariant():
    with pytest.raises(ValueError, match="Only loopback addresses are permitted"):
        BridgeDaemon(host="0.0.0.0", port=8765)
        
@pytest.mark.asyncio
async def test_bridge_health_endpoint(bridge_daemon):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://127.0.0.1:{bridge_daemon.port}/health") as resp:
            assert resp.status == 200
            data = await resp.json()
            assert data["status"] == "ok"

@pytest.mark.asyncio
async def test_bridge_origin_filtering(bridge_daemon):
    async with aiohttp.ClientSession() as session:
        # Invalid origin
        headers = {"Origin": "http://evil.example.com"}
        async with session.get(f"http://127.0.0.1:{bridge_daemon.port}/health", headers=headers) as resp:
            assert resp.status == 403
            
        # Valid origin
        headers = {"Origin": "https://jmartynov.github.io"}
        async with session.get(f"http://127.0.0.1:{bridge_daemon.port}/health", headers=headers) as resp:
            assert resp.status == 200

@pytest.mark.asyncio
async def test_bridge_csrf_token_handshake(bridge_daemon):
    async with aiohttp.ClientSession() as session:
        # Get challenge token
        async with session.get(f"http://127.0.0.1:{bridge_daemon.port}/api/v1/auth/challenge") as resp:
            assert resp.status == 200
            data = await resp.json()
            token = data["token"]
            
        # Attempt POST without token
        async with session.post(f"http://127.0.0.1:{bridge_daemon.port}/api/v1/fix") as resp:
            assert resp.status == 401
            
        # Attempt POST with wrong token
        headers = {"X-MCP-Bridge-Token": "invalid_token"}
        async with session.post(f"http://127.0.0.1:{bridge_daemon.port}/api/v1/fix", headers=headers) as resp:
            assert resp.status == 401

        # Attempt POST with correct token
        headers = {"X-MCP-Bridge-Token": token}
        async with session.post(f"http://127.0.0.1:{bridge_daemon.port}/api/v1/fix", headers=headers) as resp:
            assert resp.status == 200

@pytest.mark.asyncio
async def test_bridge_sse_progress_stream(bridge_daemon):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://127.0.0.1:{bridge_daemon.port}/api/v1/events?simulate=true") as resp:
            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "text/event-stream"
            
            content = b""
            async for chunk, _ in resp.content.iter_chunks():
                content += chunk
                
            events = content.decode('utf-8').strip().split('\n\n')
            assert len(events) == 4
            
            assert "event: scan_progress" in events[0]
            assert "discovering_clients" in events[0]
            assert '"percent": 25' in events[0]

            assert "event: scan_progress" in events[1]
            assert "probing_ports" in events[1]
            assert '"percent": 60' in events[1]

            assert "event: scan_progress" in events[2]
            assert "analyzing_drift" in events[2]
            assert '"percent": 85' in events[2]

            assert "event: scan_complete" in events[3]
            assert "done" in events[3]
            assert '"percent": 100' in events[3]

@pytest.mark.asyncio
async def test_bridge_websocket_stream(bridge_daemon):
    import base64
    import os
    
    # We use raw asyncio to verify the raw websocket handshake and frames as required by invariant.
    reader, writer = await asyncio.open_connection('127.0.0.1', bridge_daemon.port)
    
    ws_key = base64.b64encode(os.urandom(16)).decode('utf-8')
    handshake = (
        f"GET /ws/live?simulate=true HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{bridge_daemon.port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    writer.write(handshake.encode('utf-8'))
    await writer.drain()
    
    # Read handshake response
    response_line = await reader.readline()
    assert response_line == b"HTTP/1.1 101 Switching Protocols\r\n"
    
    headers = {}
    while True:
        line = await reader.readline()
        if line == b"\r\n":
            break
        key, val = line.decode('utf-8').strip().split(': ', 1)
        headers[key.lower()] = val
        
    assert headers['upgrade'] == 'websocket'
    
    # Read websocket frames
    frames = []
    while True:
        try:
            header = await reader.readexactly(2)
            opcode = header[0] & 0x0F
            if opcode == 0x8: # close
                break
                
            payload_len = header[1] & 0x7F
            if payload_len == 126:
                ext_len = await reader.readexactly(2)
                payload_len = int.from_bytes(ext_len, 'big')
            elif payload_len == 127:
                ext_len = await reader.readexactly(8)
                payload_len = int.from_bytes(ext_len, 'big')
                
            payload = await reader.readexactly(payload_len)
            frames.append(json.loads(payload.decode('utf-8')))
        except asyncio.IncompleteReadError:
            break
            
    writer.close()
    await writer.wait_closed()
    
    assert len(frames) == 4
    assert frames[0]["step"] == "discovering_clients"
    assert frames[0]["percent"] == 25
    assert frames[3]["step"] == "done"
    assert frames[3]["percent"] == 100

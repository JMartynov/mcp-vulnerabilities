import pytest
import pytest_asyncio
import json
import asyncio
from mcp_vulnerabilities.daemon.bridge import BridgeDaemon

@pytest_asyncio.fixture(loop_scope="function")
async def bridge_daemon(unused_tcp_port):
    daemon = BridgeDaemon(port=unused_tcp_port, simulate=False)
    await daemon.start()
    yield daemon
    await daemon.stop()

@pytest.mark.asyncio
async def test_bridge_stream_emit_event(bridge_daemon):
    q = asyncio.Queue()
    bridge_daemon.subscribers.append(q)
    
    await bridge_daemon.emit_event("scan_start", {"message": "Scan started"})
    
    event = await asyncio.wait_for(q.get(), timeout=1.0)
    assert event["type"] == "scan_start"
    assert event["payload"]["message"] == "Scan started"

@pytest.mark.asyncio
async def test_bridge_stream_multiple_subscribers(bridge_daemon):
    q1 = asyncio.Queue()
    q2 = asyncio.Queue()
    bridge_daemon.subscribers.append(q1)
    bridge_daemon.subscribers.append(q2)
    
    await bridge_daemon.emit_event("vulnerability_found", {"vuln": "CVE-2025-1234"})
    
    event1 = await asyncio.wait_for(q1.get(), timeout=1.0)
    event2 = await asyncio.wait_for(q2.get(), timeout=1.0)
    
    assert event1["type"] == "vulnerability_found"
    assert event1["payload"]["vuln"] == "CVE-2025-1234"
    assert event2["type"] == "vulnerability_found"
    assert event2["payload"]["vuln"] == "CVE-2025-1234"

import urllib.request
import urllib.error
import websockets
import threading

@pytest_asyncio.fixture(loop_scope="function")
async def simulate_daemon(unused_tcp_port):
    daemon = BridgeDaemon(port=unused_tcp_port, simulate=True)
    await daemon.start()
    yield daemon
    await daemon.stop()

@pytest.mark.asyncio
async def test_bridge_stream_sse_simulate(simulate_daemon):
    reader, writer = await asyncio.open_connection('127.0.0.1', simulate_daemon.port)
    request = f"GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1:{simulate_daemon.port}\r\n\r\n"
    writer.write(request.encode())
    await writer.drain()

    lines = []
    while True:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=1.0)
            if not line:
                break
            lines.append(line.decode())
            if b"event: scan_complete" in line:
                data_line = await asyncio.wait_for(reader.readline(), timeout=1.0)
                lines.append(data_line.decode())
                break
        except asyncio.TimeoutError:
            break
            
    content = "".join(lines)
    assert "event: scan_progress" in content
    assert "event: scan_complete" in content
    assert "discovering_clients" in content
    assert "done" in content

@pytest.mark.asyncio
async def test_bridge_stream_ws_simulate(simulate_daemon):
    import websockets
    uri = f"ws://127.0.0.1:{simulate_daemon.port}/ws/live"
    
    events_received = []
    try:
        async with websockets.connect(uri) as websocket:
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    events_received.append(json.loads(message))
                    if events_received[-1].get("step") == "done":
                        break
                except websockets.exceptions.ConnectionClosedOK:
                    break
    except Exception as e:
        pytest.fail(f"WebSocket connection failed: {e}")
        
    assert len(events_received) == 4
    assert events_received[0]["step"] == "discovering_clients"
    assert events_received[-1]["step"] == "done"

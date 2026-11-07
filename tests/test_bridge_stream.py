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

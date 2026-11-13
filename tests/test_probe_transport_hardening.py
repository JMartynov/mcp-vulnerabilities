import json
import queue
import subprocess
import sys
import threading
import time
import pytest
from mcp_vulnerabilities.probe.transport import (
    StdioTransport,
    HttpSseTransport,
    TransportError,
    TransportTimeoutError,
    _SENTINEL,
)


def test_stdio_transport_persistent_reader_thread():
    """Verify StdioTransport uses a single background reader thread and does not leak threads per receive."""
    # Run a simple python echo subprocess that outputs two JSON lines
    code = (
        "import sys, time\n"
        "sys.stdout.write('{\"msg\": 1}\\n')\n"
        "sys.stdout.flush()\n"
        "time.sleep(0.1)\n"
        "sys.stdout.write('{\"msg\": 2}\\n')\n"
        "sys.stdout.flush()\n"
        "time.sleep(1)\n"
    )
    transport = StdioTransport(command=sys.executable, args=["-c", code])
    transport.start()

    try:
        reader_thread = transport._stdout_thread
        assert reader_thread is not None
        assert reader_thread.is_alive()

        # First receive
        msg1 = transport.receive(timeout=2.0)
        assert msg1 == {"msg": 1}
        # Verify reader thread is STILL the exact same instance (no new thread spawned)
        assert transport._stdout_thread is reader_thread

        # Second receive
        msg2 = transport.receive(timeout=2.0)
        assert msg2 == {"msg": 2}
        assert transport._stdout_thread is reader_thread
    finally:
        transport.stop()


def test_http_sse_transport_queue_and_sentinel():
    """Verify HttpSseTransport uses queue.Queue and cleanly unblocks on stop with sentinel."""
    transport = HttpSseTransport("http://localhost:9999/sse", timeout=1.0)
    assert isinstance(transport.queue, queue.Queue)

    # Put a test message directly into queue
    transport.queue.put({"event": "test_msg", "data": 123})
    res = transport.receive(timeout=1.0)
    assert res == {"event": "test_msg", "data": 123}

    # Verify that stopping puts _SENTINEL and unblocks receive
    transport.stop()
    with pytest.raises(TransportError, match="SSE stream closed"):
        transport.receive(timeout=1.0)

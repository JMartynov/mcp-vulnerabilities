"""
Unit tests for Network Scanner (Task 115).
"""

import pytest
import asyncio
from mcp_vulnerabilities.probe.network_scanner import NetworkMCPScanner

def test_network_scanner_init():
    scanner = NetworkMCPScanner(timeout_ms=100, candidate_paths=["/", "/mcp"])
    assert scanner.timeout == 0.1
    assert scanner.candidate_paths == ["/", "/mcp"]

def test_network_scanner_tcp_timeout():
    scanner = NetworkMCPScanner(timeout_ms=50)
    async def run():
        return await scanner.check_tcp_port("127.0.0.1", 19999)
    res = asyncio.run(run())
    assert res is False

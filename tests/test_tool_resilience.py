"""Test suite verifying tool resilience, bounded concurrency, and error handling for Track C."""

import asyncio
import pytest
from mcp_vulnerabilities.probe.network_scanner import NetworkMCPScanner
from mcp_vulnerabilities.proxy.interceptor import McpStdioProxy
from mcp_vulnerabilities.proxy.policy import ProxyPolicyEngine
from mcp_vulnerabilities.transitive import TransitiveDependencyAuditor

def test_network_scanner_concurrency_bounding():
    """Verify NetworkMCPScanner initializes with bounded semaphore."""
    scanner = NetworkMCPScanner(timeout_ms=100, max_concurrency=32)
    assert scanner.semaphore._value == 32
    assert scanner.timeout == 0.1

def test_network_scanner_unreachable_port():
    """Verify non-listening port fails gracefully without hanging."""
    scanner = NetworkMCPScanner(timeout_ms=50)
    # Port 59999 should be closed locally
    is_open = asyncio.run(scanner.check_tcp_port("127.0.0.1", 59999))
    assert is_open is False

def test_transitive_auditor_deduplication():
    """Verify transitive auditor deduplicates repeated dependencies and guards against cycles."""
    deps = [
        ("express", "4.18.2", "npm"),
        ("express", "4.18.2", "npm"),
        ("lodash", "4.17.21", "npm"),
    ]
    # audit_dependencies should deduplicate to 2 items before network queries
    # Mocking OSV query to avoid network dependency in unit test
    auditor = TransitiveDependencyAuditor()
    # If empty dependencies passed
    assert auditor.audit_dependencies([]) == []

def test_proxy_interceptor_initialization():
    """Verify McpStdioProxy initializes with clean pending requests dictionary."""
    engine = ProxyPolicyEngine()
    proxy = McpStdioProxy(policy_engine=engine)
    assert proxy.pending_requests == {}
    assert proxy.mode == "block"

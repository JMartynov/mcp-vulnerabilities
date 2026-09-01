"""Unit tests for MCP relevance and domain filtering engine."""

from __future__ import annotations

from mcp_vulnerabilities.filter import McpRelevanceFilter


def test_mcp_relevance_filter_known_packages() -> None:
    is_rel, reasons = McpRelevanceFilter.is_relevant(package_name="mcp-remote")
    assert is_rel
    assert any("known MCP package" in r for r in reasons)

    is_rel2, _ = McpRelevanceFilter.is_relevant(
        package_name="@modelcontextprotocol/server-postgres"
    )
    assert is_rel2

    is_rel3, _ = McpRelevanceFilter.is_relevant(package_name="fastmcp")
    assert is_rel3


def test_mcp_relevance_filter_prefixes_and_repos() -> None:
    is_rel, reasons = McpRelevanceFilter.is_relevant(package_name="custom-database-mcp-server")
    assert is_rel
    assert any("canonical MCP naming" in r for r in reasons)

    is_rel_repo, reasons_repo = McpRelevanceFilter.is_relevant(
        repo_url="https://github.com/modelcontextprotocol/servers"
    )
    assert is_rel_repo
    assert any("Repository URL" in r for r in reasons_repo)


def test_mcp_relevance_filter_text_patterns() -> None:
    is_rel, reasons = McpRelevanceFilter.is_relevant(
        summary="DNS rebinding in Neo4j Cypher MCP server allows malicious websites..."
    )
    assert is_rel
    assert any("matches Model Context Protocol" in r or "MCP" in r for r in reasons)

    is_rel2, _ = McpRelevanceFilter.is_relevant(
        details="Vulnerability in Model Context Protocol stdio transport handler"
    )
    assert is_rel2

    # Agent host integrations
    is_rel_agent, _ = McpRelevanceFilter.is_relevant(
        summary="Roo Code AI agent project-specific MCP configuration allows remote code execution"
    )
    assert is_rel_agent

    is_rel_agent2, _ = McpRelevanceFilter.is_relevant(
        details="Data exfiltration via Slack Model Context Protocol Server and Anthropic Claude"
    )
    assert is_rel_agent2


def test_mcp_relevance_filter_rejects_microchip_hardware() -> None:
    # Microchip hardware drivers must be rejected
    is_rel, _ = McpRelevanceFilter.is_relevant(
        package_name="linux-kernel",
        summary="HID: mcp2221: prevent a buffer overflow in mcp_smbus_xfer",
        details="In the Linux kernel, heap overflow in mcp2221 driver.",
    )
    assert not is_rel

    is_rel_chip, _ = McpRelevanceFilter.is_relevant(
        package_name="pinctrl-mcp23s08",
        summary="Fix sleeping in atomic context during mcp23s08 regmap access",
    )
    assert not is_rel_chip


def test_mcp_relevance_filter_rejects_legacy_mainframes_and_proxies() -> None:
    # Unisys ClearPath Master Control Program (1960s-2021)
    is_rel_unisys, _ = McpRelevanceFilter.is_relevant(
        package_name="ClearPath-MCP",
        summary="Dynamic initialization of ClearPath MCP allows denial of service",
        details="Unisys ClearPath Forward Libra and ClearPath MCP Software Series fault",
    )
    assert not is_rel_unisys

    # McAfee Client Proxy (MCP)
    is_rel_mcafee, _ = McpRelevanceFilter.is_relevant(
        package_name="mcafee-client-proxy",
        summary="Auth Bypass in Windows client in McAfee Client Proxy (MCP)",
        details="Allows local users to bypass filtering rules.",
    )
    assert not is_rel_mcafee

    # TI Multi-Chip Package WiLink driver
    is_rel_ti, _ = McpRelevanceFilter.is_relevant(
        package_name="ti-wilink-driver",
        summary="The Texas Instruments WiLink WL18xx MCP driver flaw",
    )
    assert not is_rel_ti


def test_mcp_relevance_filter_rejects_irrelevant() -> None:
    is_rel, reasons = McpRelevanceFilter.is_relevant(
        package_name="legacy-accounting-calculator",
        summary="Buffer overflow in legacy desktop accounting tool",
        details="Parsing malformed excel spreadsheet formulas triggers heap corruption",
        repo_url="https://github.com/legacy/accounting",
    )
    assert not is_rel
    assert len(reasons) == 0

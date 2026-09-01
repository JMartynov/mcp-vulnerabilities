"""MCP Relevance and Domain Filtering Engine."""

from __future__ import annotations

from typing import Any

# Known canonical MCP package names
KNOWN_MCP_PACKAGES: frozenset[str] = frozenset(
    {
        "mcp",
        "fastmcp",
        "mcp-remote",
        "mcp-neo4j-cypher",
        "mcp-server-sqlite",
        "mcp-server-git",
        "mcp-server-figma",
        "mcp-code-review-server",
        "mcp-server-rijksmuseum",
        "doc-tools-mcp",
        "sammcj/mcp-package-docs",
        "awslabs.aws-api-mcp-server",
        "awslabs-aws-api-mcp-server",
        "@modelcontextprotocol/sdk",
        "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-sqlite",
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-git",
        "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-everything",
        "@cyanheads/git-mcp-server",
        "@aborruso/ckan-mcp-server",
        "github.com/modelcontextprotocol/go-sdk",
    }
)

MCP_CONTEXT_KEYWORDS: tuple[str, ...] = (
    "model context protocol",
    "mcp server",
    "mcp sdk",
    "mcp tool",
    "mcp client",
    "mcp configuration",
    "mcp integration",
    "mcp bridge",
    "mcp gateway",
    "mcp proxy",
    "fastmcp",
    "modelcontextprotocol",
    "claude",
    "anthropic",
    "llm",
    "ai agent",
    "agentic",
    "cursor",
    "json-rpc",
)

LEGACY_EXCLUSIONS: tuple[str, ...] = (
    "clearpath",
    "unisys",
    "mcafee client proxy",
    "mcp2221",
    "mcp23s08",
    "mcp23s17",
    "mcp2515",
    "mcp3008",
    "wilink",
)


class McpRelevanceFilter:
    """Evaluates whether a vulnerability record is directly or indirectly related to MCP."""

    @classmethod
    def is_relevant(
        cls,
        package_name: str | None = None,
        summary: str | None = None,
        details: str | None = None,
        repo_url: str | None = None,
        raw_data: dict[str, Any] | None = None,
    ) -> tuple[bool, tuple[str, ...]]:
        """Determine if a vulnerability item is relevant to MCP infrastructure.

        Returns:
            (is_relevant, reasons)
        """
        combined_text = f"{package_name or ''} {summary or ''} {details or ''}".lower()

        # Check legacy exclusions first (unless text explicitly says "Model Context Protocol")
        if "model context protocol" not in combined_text and any(
            exc in combined_text for exc in LEGACY_EXCLUSIONS
        ):
            return False, ()

        reasons: list[str] = []

        # 1. Text patterns for Model Context Protocol & MCP infrastructure
        if any(
            kw in combined_text
            for kw in (
                "model context protocol",
                "mcp server",
                "mcp sdk",
                "mcp tool",
                "mcp client",
                "mcp-server",
                "mcp configuration",
                "mcp integration",
                "mcp bridge",
                "mcp gateway",
                "fastmcp",
                "modelcontextprotocol",
                "@modelcontextprotocol",
                "cypher_query",
                "stdio transport",
                "sse transport",
            )
        ):
            reasons.append("Text explicitly matches Model Context Protocol infrastructure patterns")

        # 2. Check canonical MCP scope or known packages
        if package_name:
            norm_pkg = package_name.strip().lower()
            if norm_pkg.startswith("@modelcontextprotocol/"):
                reasons.append(f"Package belongs to @modelcontextprotocol scope: '{package_name}'")
            elif norm_pkg in {p.lower() for p in KNOWN_MCP_PACKAGES if p != "mcp"}:
                reasons.append(f"Direct match with known MCP package '{package_name}'")
            elif (
                norm_pkg.startswith("mcp-")
                or norm_pkg.endswith("-mcp-server")
                or "mcp_server" in norm_pkg
            ):
                reasons.append(
                    f"Package name '{package_name}' has canonical MCP naming prefix/suffix"
                )
            elif (norm_pkg.endswith("-mcp") or norm_pkg == "mcp") and any(
                kw in combined_text for kw in MCP_CONTEXT_KEYWORDS
            ):
                reasons.append(
                    f"Package '{package_name}' matches confirmed Model Context Protocol context"
                )

        # 3. Check repository URL
        if repo_url:
            norm_repo = repo_url.lower()
            if "modelcontextprotocol" in norm_repo or "/mcp-" in norm_repo or "-mcp" in norm_repo:
                reasons.append(f"Repository URL '{repo_url}' points to MCP organization/repository")

        # 4. Check raw dictionary structure if provided
        if raw_data and not reasons:
            raw_str = str(raw_data).lower()
            if "model context protocol" in raw_str or "@modelcontextprotocol" in raw_str:
                reasons.append("Raw payload mentions Model Context Protocol")

        is_rel = len(reasons) > 0
        return is_rel, tuple(reasons)

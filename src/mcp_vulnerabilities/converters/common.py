"""Shared helper functions and common utilities for multi-format vulnerability converters."""

from __future__ import annotations

import re

KEYWORDS: tuple[str, ...] = (
    "query",
    "get",
    "search",
    "read",
    "write",
    "exec",
    "init",
    "add",
    "diff",
    "checkout",
    "install",
    "fetch",
    "delete",
    "update",
    "cypher",
)


def infer_vulnerable_tools(text: str) -> list[str]:
    """Infer vulnerable MCP tool names mentioned in vulnerability descriptions.

    Scans text for backtick code identifiers matching keywords (e.g. `get_customer`, `cypher_query`),
    with context-aware fallbacks for common domain-specific servers (e.g. cypher_query, git_init).

    Args:
        text: The vulnerability details or description string.

    Returns:
        Sorted list of unique inferred vulnerable tool names.
    """
    if not text:
        return []

    tools: set[str] = set()
    lower = text.lower()

    for match in re.finditer(r"`([a-z][a-z0-9_]{2,30})`", text):
        candidate = match.group(1)
        if any(term in candidate for term in KEYWORDS):
            tools.add(candidate)

    # Context-aware fallback for domain-specific servers
    if not tools:
        if "cypher query" in lower or "cypher" in lower:
            tools.add("cypher_query")
        elif "git_init" in lower:
            tools.add("git_init")

    return sorted(tools)


# Backward-compatible alias for tests/callers expecting private identifier
_infer_vulnerable_tools = infer_vulnerable_tools

__all__ = ["_infer_vulnerable_tools", "infer_vulnerable_tools"]

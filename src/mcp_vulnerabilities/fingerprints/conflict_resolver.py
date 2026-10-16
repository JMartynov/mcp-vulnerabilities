"""Re-export shim for conflict_resolver."""

from mcp_vulnerabilities.audit.conflict_resolver import (
    ResolveResult,
    resolve_client_config,
)

__all__ = [
    "ResolveResult",
    "resolve_client_config",
]

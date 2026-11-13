"""CLI package for MCP Vulnerability Advisory Database."""

from __future__ import annotations

import argparse
import sys
from typing import Callable

from mcp_vulnerabilities.audit import (
    ClientConfigFixer,
    ClientConfigParser,
    DiscoveredClientServer,
    UniversalClientConfigScanner,
    VulnerabilityMatcher,
)
from mcp_vulnerabilities.cli.common import console, logger
from mcp_vulnerabilities.cli.handlers.audit import (
    handle_audit,
    handle_audit_transitive,
    handle_audit_typosquat,
    handle_export_config,
    handle_fix,
    handle_hub,
    handle_remediate_pr,
    handle_resolve_config,
)
from mcp_vulnerabilities.cli.handlers.catalog import (
    handle_correlate,
    handle_export_airgap,
    handle_export_osv,
    handle_lookup,
    handle_search,
    handle_site_build,
    handle_snapshot,
    handle_timeline,
    handle_validate,
    handle_verify_feed,
)
from mcp_vulnerabilities.cli.handlers.daemon import (
    handle_bridge,
    handle_monitor,
    handle_serve,
    handle_tui,
)
from mcp_vulnerabilities.cli.handlers.misc import (
    handle_lint,
    handle_sandbox,
)
from mcp_vulnerabilities.cli.handlers.probe import (
    handle_identify,
    handle_network_scan,
    handle_probe,
    handle_probe_safe,
    handle_scan_binaries,
    handle_scan_source,
)
from mcp_vulnerabilities.cli.handlers.proxy import handle_proxy
from mcp_vulnerabilities.cli.handlers.sync import (
    handle_discover,
    handle_enrich,
    handle_sync,
)
from mcp_vulnerabilities.cli.parser import create_parser
from mcp_vulnerabilities.probe.client import McpProbeClient
from mcp_vulnerabilities.provenance import resolve_provenance_urls
from mcp_vulnerabilities.transitive import TransitiveDependencyAuditor

HANDLERS: dict[str, Callable[[argparse.Namespace], None]] = {
    "proxy": handle_proxy,
    "site-build": handle_site_build,
    "discover": handle_discover,
    "enrich": handle_enrich,
    "sync": handle_sync,
    "validate": handle_validate,
    "export-osv": handle_export_osv,
    "snapshot": handle_snapshot,
    "export-airgap": handle_export_airgap,
    "search": handle_search,
    "lookup": handle_lookup,
    "audit": handle_audit,
    "audit-config": handle_audit,
    "audit-typosquat": handle_audit_typosquat,
    "audit-transitive": handle_audit_transitive,
    "hub": handle_hub,
    "remediate-pr": handle_remediate_pr,
    "fix": handle_fix,
    "fix-config": handle_fix,
    "identify": handle_identify,
    "scan-binaries": handle_scan_binaries,
    "probe": handle_probe,
    "probe-safe": handle_probe_safe,
    "scan-source": handle_scan_source,
    "serve": handle_serve,
    "lint": handle_lint,
    "network-scan": handle_network_scan,
    "tui": handle_tui,
    "monitor": handle_monitor,
    "bridge": handle_bridge,
    "sandbox": handle_sandbox,
    "timeline": handle_timeline,
    "verify-feed": handle_verify_feed,
    "correlate": handle_correlate,
    "resolve-config": handle_resolve_config,
    "export-config": handle_export_config,
}


def main(args: list[str] | None = None) -> None:
    parser = create_parser()
    parsed_args = parser.parse_args(args)
    handler = HANDLERS.get(parsed_args.command)
    if handler:
        handler(parsed_args)
    else:
        parser.print_help()
        sys.exit(1)


__all__ = [
    "main",
    "create_parser",
    "console",
    "logger",
    "McpProbeClient",
    "VulnerabilityMatcher",
    "ClientConfigParser",
    "TransitiveDependencyAuditor",
    "ClientConfigFixer",
    "DiscoveredClientServer",
    "UniversalClientConfigScanner",
    "resolve_provenance_urls",
]

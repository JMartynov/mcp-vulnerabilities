"""Backward-compatibility shim for EPSS threat intelligence module.

Deprecated: Use `mcp_vulnerabilities.threat_intel.epss` instead.
"""

from mcp_vulnerabilities.threat_intel.epss import EpssClient, EpssScore

__all__ = ["EpssScore", "EpssClient"]

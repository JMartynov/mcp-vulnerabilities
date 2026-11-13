"""Backward-compatibility shim for database vulnerability matcher.

Deprecated: `mcp_vulnerabilities.database.matcher` is deprecated.
Use `mcp_vulnerabilities.audit.matcher.VulnerabilityMatcher` instead.
"""

import warnings
from pathlib import Path

from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher as AuditVulnerabilityMatcher


class VulnerabilityMatcher:
    """Deprecated compatibility wrapper delegating to audit.matcher.VulnerabilityMatcher.

    .. deprecated::
        Use :class:`mcp_vulnerabilities.audit.matcher.VulnerabilityMatcher` instead.
    """

    def __init__(self, vulnerabilities_dir: Path | str | None) -> None:
        warnings.warn(
            "mcp_vulnerabilities.database.matcher.VulnerabilityMatcher is deprecated. "
            "Use mcp_vulnerabilities.audit.matcher.VulnerabilityMatcher instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.vulnerabilities_dir = Path(vulnerabilities_dir) if vulnerabilities_dir else None
        if self.vulnerabilities_dir and self.vulnerabilities_dir.exists():
            if self.vulnerabilities_dir.is_file():
                self._matcher = AuditVulnerabilityMatcher.from_snapshot(self.vulnerabilities_dir)
            else:
                self._matcher = AuditVulnerabilityMatcher.from_directory(self.vulnerabilities_dir, recursive=True)
        else:
            self._matcher = AuditVulnerabilityMatcher([])

    def get_vulnerable_tools(self, package_name: str) -> set[str]:
        """Extracts vulnerable tool names associated with a package."""
        return self._matcher.get_vulnerable_tools(package_name)


__all__ = ["VulnerabilityMatcher"]

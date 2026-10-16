"""Re-export shim for conflict_detector."""

from mcp_vulnerabilities.audit.conflict_detector import (
    ConflictAuditReport,
    ConflictDetector,
    ToolCollision,
    ToolInstance,
    audit_client_config,
    extract_package_from_server_config,
    format_audit_report,
    load_passport_index,
)

__all__ = [
    "ConflictDetector",
    "ToolInstance",
    "ToolCollision",
    "ConflictAuditReport",
    "audit_client_config",
    "format_audit_report",
    "extract_package_from_server_config",
    "load_passport_index",
]

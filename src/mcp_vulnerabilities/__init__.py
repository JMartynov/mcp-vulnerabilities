"""Open Source Vulnerability (OSV v1.6.0) ingestion and normalization engine."""

from mcp_vulnerabilities.converters.ghsa import GhsaConverter
from mcp_vulnerabilities.converters.markdown_cve import MarkdownAdvisoryConverter
from mcp_vulnerabilities.converters.nvd import NvdConverter
from mcp_vulnerabilities.converters.osv_dev import OsvDevConverter
from mcp_vulnerabilities.converters.verity import VerityCatalogConverter
from mcp_vulnerabilities.deduplicator import OsvDeduplicator
from mcp_vulnerabilities.models import (
    AffectedPackage,
    DatabaseSpecificMcp,
    EventSpec,
    OsvVulnerability,
    PackageSpec,
    RangeSpec,
    RangeType,
    ReferenceSpec,
    ReferenceType,
    SeveritySpec,
    SeverityType,
    build_purl,
    parse_purl,
)
from mcp_vulnerabilities.pipeline import McpVulnerabilityPipeline, PipelineResult
from mcp_vulnerabilities.validator import OsvValidationError, OsvValidator

__all__ = [
    "AffectedPackage",
    "DatabaseSpecificMcp",
    "EventSpec",
    "GhsaConverter",
    "MarkdownAdvisoryConverter",
    "McpVulnerabilityPipeline",
    "NvdConverter",
    "OsvDeduplicator",
    "OsvDevConverter",
    "OsvValidationError",
    "OsvValidator",
    "OsvVulnerability",
    "PackageSpec",
    "PipelineResult",
    "RangeSpec",
    "RangeType",
    "ReferenceSpec",
    "ReferenceType",
    "SeveritySpec",
    "SeverityType",
    "VerityCatalogConverter",
    "build_purl",
    "parse_purl",
]

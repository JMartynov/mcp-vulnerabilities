"""Converter for Verity internal benchmark vulnerability conditions."""

from __future__ import annotations

from typing import Any
import logging

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
    build_purl,
)

logger = logging.getLogger("mcp_vulnerabilities.converters.verity")

try:
    from verity_lite.mcp_catalog import McpServerSpec, VulnerabilityCondition, list_server_specs
    HAVE_VERITY_CATALOG = True
except ImportError:
    HAVE_VERITY_CATALOG = False
    McpServerSpec = Any  # type: ignore
    VulnerabilityCondition = Any  # type: ignore
    def list_server_specs() -> list[Any]:
        return []


class VerityCatalogConverter:
    """Converts internal benchmark targets and condition catalogs into canonical OSV records."""

    @classmethod
    def convert_condition(
        cls,
        server_spec: Any,
        cond: Any,
    ) -> OsvVulnerability:
        """Convert a single Verity VulnerabilityCondition into an OsvVulnerability."""
        vuln_id = f"VERITY-{cond.condition_id}"
        purl = build_purl("mcp", server_spec.server_id, getattr(server_spec, "dataset_version", "1.0.0"))

        db_mcp = DatabaseSpecificMcp(
            vulnerable_tools=(cond.target_tool,),
            cwe_ids=(cond.cwe_id,),
            owasp_mcp_category=cond.category,
            severity="HIGH",
            cvss_score=8.5,
            remediation_guidance=cond.secure_mitigation,
            verity_condition_id=cond.condition_id,
        )

        affected_pkg = AffectedPackage(
            package=PackageSpec(
                name=server_spec.server_id,
                ecosystem="MCP",
                purl=purl,
            ),
            ranges=(
                RangeSpec(
                    type=RangeType.SEMVER,
                    events=(
                        EventSpec(introduced="0.1.0"),
                        EventSpec(fixed="1.0.0-secure"),
                    ),
                ),
            ),
            database_specific=db_mcp,
        )

        details = (
            f"### Vulnerability Condition: {cond.name}\n\n"
            f"**Category**: {cond.category}\n"
            f"**CWE**: {cond.cwe_id}\n"
            f"**Target Tool**: `{cond.target_tool}`\n\n"
            f"#### Vulnerable Behavior\n{cond.vulnerable_behavior}\n\n"
            f"#### Secure Mitigation\n{cond.secure_mitigation}\n\n"
            f"#### Description\n{cond.description}"
        )

        return OsvVulnerability(
            id=vuln_id,
            summary=f"{cond.name} in {server_spec.name} ({server_spec.server_id})",
            details=details,
            published="2026-01-01T00:00:00Z",
            modified="2026-08-21T00:00:00Z",
            aliases=(cond.condition_id,),
            affected=(affected_pkg,),
            references=(
                ReferenceSpec(
                    url=f"https://github.com/JMartynov/mcp-vulnerabilities/blob/main/data/vulnerabilities/{vuln_id}.json",
                    type=ReferenceType.PACKAGE,
                ),
            ),
            database_specific={
                "source": "Verity Benchmark Catalog",
                "server_id": server_spec.server_id,
                "benchmark_domain": getattr(server_spec, "domain", "benchmark"),
            },
        )

    @classmethod
    def convert_all(cls) -> list[OsvVulnerability]:
        """Convert all conditions across all benchmark servers in the catalog."""
        if not HAVE_VERITY_CATALOG:
            logger.debug("verity_lite catalog not available in environment; skipping Verity catalog conversion.")
            return []
        records: list[OsvVulnerability] = []
        for spec in list_server_specs():
            for cond in spec.vulnerabilities:
                records.append(cls.convert_condition(spec, cond))
        return records

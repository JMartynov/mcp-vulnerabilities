from pathlib import Path
from mcp_vulnerabilities.converters.gitlab import GitLabConverter
from mcp_vulnerabilities.models import OsvVulnerability, RangeType, SeverityType
from mcp_vulnerabilities.pipeline import McpVulnerabilityPipeline
from mcp_vulnerabilities.deduplicator import OsvDeduplicator

def test_gitlab_yaml_parsing():
    # INVARIANT_149_1
    vuln = GitLabConverter.from_file("tests/fixtures/osv/gitlab/CVE-2024-54133.yml")
    assert vuln.id == "CVE-2024-54133"
    assert vuln.aliases == ("GHSA-w48q-v783-6mg3",)
    assert vuln.affected[0].package.ecosystem == "npm"
    assert vuln.affected[0].package.name == "@modelcontextprotocol/server-postgres"
    assert vuln.affected[0].package.purl == "pkg:npm/@modelcontextprotocol/server-postgres"
    assert vuln.summary == "Improper Input Validation in MCP Postgres Server"

def test_gitlab_range_syntax_conversion():
    # INVARIANT_149_2
    vuln = GitLabConverter.from_file("tests/fixtures/osv/gitlab/CVE-2024-54133.yml")
    ranges = vuln.affected[0].ranges
    assert len(ranges) == 1
    assert ranges[0].type == RangeType.SEMVER
    events = ranges[0].events
    # from >=0.1.0 <0.3.2
    assert len(events) == 2
    assert events[0].introduced == "0.1.0"
    assert events[1].fixed == "0.3.2"

def test_gitlab_cvss_vector_extraction():
    # INVARIANT_149_3
    vuln = GitLabConverter.from_file("tests/fixtures/osv/gitlab/CVE-2024-54133.yml")
    assert len(vuln.severity) == 1
    assert vuln.severity[0].type == SeverityType.CVSS_V3
    assert vuln.severity[0].score == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert vuln.affected[0].database_specific.cvss_v3_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

def test_gitlab_remediation_solution_preservation():
    vuln = GitLabConverter.from_file("tests/fixtures/osv/gitlab/CVE-2024-54133.yml")
    assert vuln.database_specific["remediation"] == "Upgrade to version 0.3.2 or above."
    assert vuln.affected[0].database_specific.remediation_guidance == "Upgrade to version 0.3.2 or above."

def test_gitlab_pipeline_dedup_integration():
    # INVARIANT_149_4
    vuln1 = GitLabConverter.from_file("tests/fixtures/osv/gitlab/CVE-2024-54133.yml")
    
    vuln2 = OsvVulnerability(
        id="GHSA-w48q-v783-6mg3",
        summary="A duplicate",
        details="Duplicate details",
        aliases=("CVE-2024-54133",),
    )
    
    merged = OsvDeduplicator.deduplicate_and_merge([vuln1, vuln2])
    # Expect 1 canonical record since they alias each other
    assert len(merged) == 1
    record = merged[0]
    # GHSA generally becomes the ID if both are present in the list depending on standard priority,
    # or CVE. Let's just check that they are merged.
    assert "CVE-2024-54133" in record.aliases or record.id == "CVE-2024-54133"
    assert "GHSA-w48q-v783-6mg3" in record.aliases or record.id == "GHSA-w48q-v783-6mg3"
    

import pytest
from mcp_vulnerabilities.dedup.fusion import AdvisoryFusionEngine
from mcp_vulnerabilities.graph.alias_graph import CanonicalAliasGraph
from mcp_vulnerabilities.models import (
    OsvVulnerability,
    SeveritySpec,
    SeverityType,
    ReferenceSpec,
    ReferenceType,
    AffectedPackage,
    PackageSpec,
    RangeSpec,
    RangeType,
    EventSpec,
    DatabaseSpecificMcp,
)

def test_multi_source_convergence():
    nvd = OsvVulnerability(
        id="CVE-2023-1234",
        summary="NVD Summary",
        details="NVD Details",
        aliases=("GHSA-1234-abcd-5678",),
        severity=(SeveritySpec(type=SeverityType.CVSS_V3, score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),),
        references=(
            ReferenceSpec(url="https://example.com/advisory?utm_source=test", type=ReferenceType.ADVISORY),
            ReferenceSpec(url="https://github.com/advisories/GHSA-1234-abcd-5678", type=ReferenceType.WEB),
        ),
        affected=(
            AffectedPackage(
                package=PackageSpec(name="test-pkg", ecosystem="PyPI", purl="pkg:pypi/test-pkg"),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(
                            EventSpec(introduced="0"),
                            EventSpec(fixed="1.2.0"),
                        )
                    ),
                ),
                versions=("1.0.0", "1.1.0"),
                database_specific=DatabaseSpecificMcp(cvss_score=9.8)
            ),
        )
    )

    ghsa = OsvVulnerability(
        id="GHSA-1234-abcd-5678",
        summary="GHSA Summary (More specific)",
        details="GHSA Details with PoC",
        aliases=("CVE-2023-1234",),
        severity=(SeveritySpec(type=SeverityType.CVSS_V3, score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),),
        references=(
            ReferenceSpec(url="https://example.com/advisory", type=ReferenceType.ADVISORY),
            ReferenceSpec(url="https://poc.com/", type=ReferenceType.EVIDENCE),
        ),
        affected=(
            AffectedPackage(
                package=PackageSpec(name="test-pkg", ecosystem="PyPI", purl="pkg:pypi/test-pkg"),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(
                            EventSpec(introduced="1.0.0"),
                            EventSpec(fixed="1.2.0"),
                        )
                    ),
                ),
                versions=("1.0.0", "1.1.0", "1.1.5"),
                database_specific=DatabaseSpecificMcp(epss_score=0.5)
            ),
        )
    )
    
    gitlab = OsvVulnerability(
        id="GLAD-2023-0001",
        summary="GitLab Advisory",
        details="GLAD Details",
        aliases=("CVE-2023-1234",),
        severity=(),
        references=(
            ReferenceSpec(url="https://gitlab.com/issue/1", type=ReferenceType.REPORT),
        ),
        affected=(
            AffectedPackage(
                package=PackageSpec(name="test-pkg", ecosystem="PyPI", purl="pkg:pypi/test-pkg"),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(
                            EventSpec(introduced="1.1.0"),
                            EventSpec(fixed="1.3.0"),
                        )
                    ),
                ),
                versions=("1.1.0", "1.2.0"),
            ),
        )
    )

    pypa = OsvVulnerability(
        id="PYSEC-2023-4321",
        summary="PyPA Advisory",
        details="PyPA Details",
        aliases=("GHSA-1234-abcd-5678", "CVE-2023-1234"),
        severity=(),
        references=(),
        affected=(
            AffectedPackage(
                package=PackageSpec(name="test-pkg", ecosystem="PyPI", purl="pkg:pypi/test-pkg"),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(
                            EventSpec(introduced="0"),
                            EventSpec(fixed="1.2.0"),
                        )
                    ),
                ),
                versions=(),
            ),
        )
    )

    engine = AdvisoryFusionEngine()
    fused = engine.fuse_all([nvd, ghsa, gitlab, pypa])
    
    assert len(fused) == 1
    v = fused[0]
    
    assert v.id == "CVE-2023-1234"
    
    assert list(v.aliases) == sorted(["GHSA-1234-abcd-5678", "GLAD-2023-0001", "PYSEC-2023-4321"])
    
    # NVD should take precedence for severity
    assert len(v.severity) == 1
    assert v.severity[0].score == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    # Check normalized references (trailing slashes stripped, query params stripped in fusion)
    urls = [r.url for r in v.references]
    assert "https://example.com/advisory" in urls
    # Ensure query string was stripped
    assert "https://example.com/advisory?utm_source=test" not in urls
    assert "https://poc.com/" in urls
    assert "https://gitlab.com/issue/1" in urls
    assert "https://github.com/advisories/GHSA-1234-abcd-5678" in urls
    
    assert len(v.affected) == 1
    aff = v.affected[0]
    assert aff.package.name == "test-pkg"
    assert list(aff.versions) == sorted(["1.0.0", "1.1.0", "1.1.5", "1.2.0"])
    
    assert len(aff.ranges) == 1
    r = aff.ranges[0]
    
    # Merged events should be 0 to 1.3.0 since we had (0, 1.2.0), (1.0.0, 1.2.0), and (1.1.0, 1.3.0)
    assert len(r.events) == 2
    assert r.events[0].introduced == "0"
    assert r.events[1].fixed == "1.3.0"
    
    assert aff.database_specific.cvss_score == 9.8
    assert aff.database_specific.epss_score == 0.5


def test_circular_alias_graph_loops():
    graph = CanonicalAliasGraph()
    graph.add_aliases("A", ["B"])
    graph.add_aliases("B", ["C"])
    graph.add_aliases("C", ["A", "D"])
    
    clusters = graph.get_all_clusters()
    assert len(clusters) == 1
    assert sorted(list(clusters[0])) == ["A", "B", "C", "D"]


def test_single_source_advisory():
    vuln = OsvVulnerability(
        id="CVE-2024-0001",
        summary="Test",
        details="Test",
        aliases=(),
        severity=(),
        affected=(),
        references=()
    )
    
    engine = AdvisoryFusionEngine()
    fused = engine.fuse_all([vuln])
    assert len(fused) == 1
    assert fused[0].id == "CVE-2024-0001"


def test_missing_summary_details():
    # Advisory 1 with missing details/summary fallback behavior test
    vuln1 = OsvVulnerability(
        id="CVE-2024-0002",
        summary="Short",
        details="Short detail",
        aliases=("GHSA-test",),
    )
    # create a mock dictionary to skip validation checks
    vuln2_dict = vuln1.to_dict()
    vuln2_dict["id"] = "GHSA-test"
    vuln2_dict["aliases"] = ["CVE-2024-0002"]
    vuln2_dict["summary"] = "Longer summary here"
    vuln2_dict["details"] = "Longer details are present"
    vuln2 = OsvVulnerability.from_dict(vuln2_dict)
    
    engine = AdvisoryFusionEngine()
    fused = engine.fuse_all([vuln1, vuln2])
    
    assert len(fused) == 1
    v = fused[0]
    assert v.id == "CVE-2024-0002"
    # CVE/NVD preferred for summary, shortest string wins tie-breaker
    assert v.summary == "Short"
    assert v.details == "Longer details are present"


def test_non_standard_version_ranges():
    vuln1 = OsvVulnerability(
        id="CVE-2024-0003",
        summary="Test",
        details="Test",
        aliases=(),
        affected=(
             AffectedPackage(
                package=PackageSpec(name="test-pkg", ecosystem="PyPI"),
                ranges=(
                    RangeSpec(
                        type=RangeType.ECOSYSTEM,
                        events=(
                            EventSpec(introduced="0"),
                            EventSpec(last_affected="1.2.0-beta"),
                        )
                    ),
                ),
            ),
        )
    )
    vuln2 = OsvVulnerability(
        id="CVE-2024-0003",
        summary="Test",
        details="Test",
        aliases=(),
        affected=(
             AffectedPackage(
                package=PackageSpec(name="test-pkg", ecosystem="PyPI"),
                ranges=(
                    RangeSpec(
                        type=RangeType.ECOSYSTEM,
                        events=(
                            EventSpec(introduced="1.2.0-beta"),
                            EventSpec(limit="1.3.0"),
                        )
                    ),
                ),
            ),
        )
    )
    
    engine = AdvisoryFusionEngine()
    fused = engine.fuse_all([vuln1, vuln2])
    
    assert len(fused) == 1
    v = fused[0]
    
    assert len(v.affected) == 1
    aff = v.affected[0]
    assert len(aff.ranges) == 1
    r = aff.ranges[0]
    assert len(r.events) == 2
    assert r.events[0].introduced == "1.2.0-beta"
    assert r.events[1].limit == "1.3.0"

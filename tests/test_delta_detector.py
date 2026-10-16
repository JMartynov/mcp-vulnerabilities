import pytest
from mcp_vulnerabilities.models import (
    OsvVulnerability,
    AffectedPackage,
    PackageSpec,
    RangeSpec,
    RangeType,
    EventSpec,
    SeveritySpec,
    SeverityType,
)
from mcp_vulnerabilities.delta_detector import DeltaDetector


def make_vuln(vuln_id="CVE-123", summary="Test", details="Test", affected=None, severity=None):
    return OsvVulnerability(
        id=vuln_id,
        summary=summary,
        details=details,
        affected=affected or tuple(),
        severity=severity or tuple(),
    )


def test_no_deltas():
    detector = DeltaDetector()
    v1 = make_vuln()
    assert not detector.evaluate_deltas([v1], [v1])


def test_new_advisory():
    detector = DeltaDetector()
    v1 = make_vuln(vuln_id="1")
    v2 = make_vuln(vuln_id="2")
    assert detector.evaluate_deltas([v1], [v1, v2])


def test_range_change():
    detector = DeltaDetector()
    affected1 = AffectedPackage(
        package=PackageSpec(name="test", ecosystem="PyPI"),
        ranges=(RangeSpec(type=RangeType.SEMVER, events=(EventSpec(introduced="1.0"), EventSpec(fixed="2.0"))),),
    )
    affected2 = AffectedPackage(
        package=PackageSpec(name="test", ecosystem="PyPI"),
        ranges=(RangeSpec(type=RangeType.SEMVER, events=(EventSpec(introduced="1.0"), EventSpec(fixed="2.1"))),),
    )

    v1 = make_vuln(affected=(affected1,))
    v2 = make_vuln(affected=(affected2,))

    assert detector.evaluate_deltas([v1], [v2])


def test_severity_change():
    detector = DeltaDetector()
    sev1 = SeveritySpec(type=SeverityType.CVSS_V3, score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    sev2 = SeveritySpec(type=SeverityType.CVSS_V3, score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L")

    v1 = make_vuln(severity=(sev1,))
    v2 = make_vuln(severity=(sev2,))

    assert detector.evaluate_deltas([v1], [v2])

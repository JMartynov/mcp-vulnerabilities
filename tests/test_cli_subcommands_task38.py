import subprocess
import sys
import pytest
from pathlib import Path

from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher
from mcp_vulnerabilities.fingerprints.correlator import VulnerabilityCorrelator
from mcp_vulnerabilities.fingerprints.models import (
    ServerPackageSpec,
    VersionFingerprint,
)


def test_cli_subcommands_help():
    cmds = ["resolve-config", "export-config", "timeline", "correlate"]
    for cmd in cmds:
        res = subprocess.run(
            [sys.executable, "-m", "mcp_vulnerabilities.cli", cmd, "--help"],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"{cmd} --help failed: {res.stderr}"
        assert "usage:" in res.stdout.lower()


def test_vulnerability_correlator_in_memory():
    adv = {
        "id": "CVE-2026-9999",
        "schema_version": "1.6.0",
        "summary": "Sample CVE",
        "details": "Details of the vulnerability",
        "affected": [
            {
                "package": {"name": "test-server", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                    }
                ],
            }
        ],
    }
    matcher = VulnerabilityMatcher([adv])

    vf1 = VersionFingerprint(version="1.0.0", toolset_canonical_hash="h1")
    vf2 = VersionFingerprint(version="2.0.0", toolset_canonical_hash="h2")
    spec = ServerPackageSpec(
        package_name="test-server",
        purl="pkg:npm/test-server",
        ecosystem="npm",
        versions=(vf1, vf2),
    )

    correlator = VulnerabilityCorrelator(matcher=matcher, passports={"test-server": spec})
    timeline = correlator.correlate_package("test-server")

    assert timeline is not None
    assert timeline.package_name == "test-server"
    assert len(timeline.timeline) == 2
    assert timeline.timeline[0].version == "1.0.0"
    assert timeline.timeline[0].is_vulnerable is True
    assert timeline.timeline[1].version == "2.0.0"
    assert timeline.timeline[1].is_vulnerable is False

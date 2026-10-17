import pytest
from mcp_vulnerabilities.catalog import (
    compute_remediation_target,
    generate_upgrade_command,
    VersionSecurityRecord
)

def test_compute_remediation_target():
    v1 = VersionSecurityRecord(version="1.0.0", is_vulnerable=True, advisories=[])
    v2 = VersionSecurityRecord(version="1.0.1", is_vulnerable=True, advisories=[])
    v3 = VersionSecurityRecord(version="1.1.0", is_vulnerable=False, advisories=[])
    v4 = VersionSecurityRecord(version="1.2.0", is_vulnerable=False, advisories=[])
    
    versions = [v1, v2, v3, v4]
    
    assert compute_remediation_target("1.0.0", versions) == "1.1.0"
    assert compute_remediation_target("1.0.1", versions) == "1.1.0"
    assert compute_remediation_target("1.1.0", versions) == "1.1.0"
    
    v5 = VersionSecurityRecord(version="2.0.0", is_vulnerable=True, advisories=[])
    versions.append(v5)
    
    assert compute_remediation_target("2.0.0", versions) is None

    from mcp_vulnerabilities.catalog import build_unified_mcp_security_catalog
    from mcp_vulnerabilities.fingerprints.models import ServerPackageSpec, VersionFingerprint
    import json
    import tempfile
    from pathlib import Path

def test_generate_upgrade_command():
    assert generate_upgrade_command("npm", "test-pkg", "1.1.0") == "npm install test-pkg@^1.1.0"
    assert generate_upgrade_command("pypi", "test-pkg", "1.1.0") == "pip install --upgrade test-pkg>=1.1.0"
    assert generate_upgrade_command("docker", "test/pkg", "1.1.0") == "docker pull test/pkg:1.1.0"
    assert generate_upgrade_command("unknown", "test-pkg", "1.1.0") is None
    assert generate_upgrade_command("npm", "test-pkg", None) is None

def test_no_fix_available_logic(tmp_path):
    from mcp_vulnerabilities.catalog import build_unified_mcp_security_catalog
    from mcp_vulnerabilities.fingerprints.models import ServerPackageSpec, VersionFingerprint
    import json
    
    passports_dir = tmp_path / "passports"
    passports_dir.mkdir()
    
    vf = VersionFingerprint(version="1.0.0", toolset_canonical_hash="t_hash")
    pkg = ServerPackageSpec(
        package_name="@test/unpatched",
        purl="pkg:npm/%40test/unpatched",
        ecosystem="npm",
        versions=(vf,)
    )
    
    pkg_file = passports_dir / "test_pkg.json"
    pkg_file.write_text(json.dumps(pkg.to_dict()))
    
    vuln_dir = tmp_path / "vulnerabilities"
    vuln_dir.mkdir()
    
    advisory_data = {
        "id": "GHSA-test-9999",
        "schema_version": "1.6.0",
        "summary": "Unpatched vuln",
        "details": "No fix",
        "affected": [{
            "package": {"name": "@test/unpatched", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
        }]
    }
    adv_file = vuln_dir / "GHSA-test-9999.json"
    adv_file.write_text(json.dumps(advisory_data))
    
    catalog = build_unified_mcp_security_catalog(passports_path=passports_dir, vulnerabilities_dir=vuln_dir)
    record = catalog["@test/unpatched"]
    v1 = record.versions[0]
    
    assert v1.is_vulnerable is True
    assert v1.recommended_update_version is None
    assert v1.no_fix_available is True

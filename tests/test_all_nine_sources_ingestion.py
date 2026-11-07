import json
import pytest
from pathlib import Path
from mcp_vulnerabilities.models import OsvVulnerability, RangeType
from mcp_vulnerabilities.validator import OsvValidator
from mcp_vulnerabilities.provenance import resolve_provenance_urls

# Actual imports
from mcp_vulnerabilities.converters.ghsa import GhsaConverter
from mcp_vulnerabilities.converters.nvd import NvdConverter
from mcp_vulnerabilities.converters.cve_json5 import CveJson5Converter
from mcp_vulnerabilities.converters.osv_dev import OsvDevConverter
from mcp_vulnerabilities.converters.pypa import PyPaAdvisoryConverter
from mcp_vulnerabilities.converters.gitlab import GitLabAdvisoryConverter
from mcp_vulnerabilities.converters.openssf_malware import OpenSsfMalwareConverter
from mcp_vulnerabilities.threat_intel.cisa_kev import CisaKevClient
from mcp_vulnerabilities.threat.epss import EpssClient
from mcp_vulnerabilities.converters.verity import VerityCatalogConverter
from mcp_vulnerabilities.converters.markdown_cve import MarkdownAdvisoryConverter

# Aliases requested by the reviewer
convert_ghsa_to_osv = GhsaConverter.from_dict
NvdApiConverter = NvdConverter
convert_nvd_to_osv = NvdConverter.from_dict
convert_osv_dev_to_canonical = OsvDevConverter.from_dict
PypaAdvisoryConverter = PyPaAdvisoryConverter
OpenSsfMaliciousSync = OpenSsfMalwareConverter
CisaKevEnricher = CisaKevClient
VerityConverter = VerityCatalogConverter
MarkdownCveConverter = MarkdownAdvisoryConverter


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "osv"

def assert_common_validations(osv: OsvVulnerability):
    # 1. Schema Validation (0 violations)
    errors = OsvValidator.validate(osv)
    assert not errors, f"Schema violations found: {errors}"
    
    # 2. Timestamp Validation
    if osv.published and osv.modified:
        assert osv.published <= osv.modified, "published must be <= modified"
        
    # 3. Affected package names, ecosystems, and PURLs
    assert len(osv.affected) > 0, "No affected packages found"
    for aff in osv.affected:
        assert aff.package.name, "Package name is required"
        assert aff.package.ecosystem, "Package ecosystem is required"
        assert aff.package.purl, "Package PURL is required"
        assert aff.package.purl.startswith("pkg:"), "Invalid PURL format"
        
    # 4. Provenance URLs resolve cleanly
    aliases = osv.aliases or ()
    prov_urls = resolve_provenance_urls(osv.id, aliases)
    assert "osv" in prov_urls, "OSV provenance URL must be present"
    if osv.id.startswith("CVE-") or any(a.startswith("CVE-") for a in aliases):
        assert "cve" in prov_urls and "nvd" in prov_urls
    if osv.id.startswith("GHSA-") or any(a.startswith("GHSA-") for a in aliases):
        assert "ghsa" in prov_urls

def test_ghsa_converter():
    path = FIXTURES_DIR / "ghsa" / "GHSA-6xpm-ggf7-wc3p.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    osv = convert_ghsa_to_osv(data)
    assert_common_validations(osv)
    assert osv.id.startswith("GHSA-")

def test_nvd_converter():
    path = FIXTURES_DIR / "nvd" / "CVE-2025-6514.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    osv = convert_nvd_to_osv(data)
    assert_common_validations(osv)
    assert osv.id.startswith("CVE-")

def test_cve_json5_converter():
    path = FIXTURES_DIR / "cve_json5" / "CVE-2025-10193.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    osv = CveJson5Converter.from_dict(data)
    assert_common_validations(osv)
    assert osv.id.startswith("CVE-")

def test_osv_dev_converter():
    path = FIXTURES_DIR / "osv_dev" / "PYSEC-2026-3482.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    osv = convert_osv_dev_to_canonical(data)
    assert_common_validations(osv)
    assert osv.id.startswith("PYSEC-") or osv.id.startswith("GHSA-") or osv.id.startswith("CVE-")

def test_pypa_converter():
    # Constructing PyPA advisory data
    data = {
        "id": "PYSEC-2026-9999",
        "summary": "Test PyPA Advisory",
        "details": "Details",
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-01-02T00:00:00Z",
        "affected": [
            {
                "package": {
                    "name": "test-pkg",
                    "ecosystem": "PyPI",
                    "purl": "pkg:pypi/test-pkg"
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.0.0"}
                        ]
                    }
                ]
            }
        ],
        "references": []
    }
    osv = PypaAdvisoryConverter.from_dict(data)
    assert_common_validations(osv)

def test_gitlab_converter():
    path = FIXTURES_DIR / "gitlab" / "CVE-2024-54133.yml"
    osv = GitLabAdvisoryConverter.from_file(path)
    assert_common_validations(osv)

def test_openssf_malware_converter():
    data = {
        "id": "MAL-2024-1111",
        "summary": "Malicious package",
        "details": "Malicious code detected",
        "published": "2024-01-01T00:00:00Z",
        "modified": "2024-01-01T00:00:00Z",
        "affected": [
            {
                "package": {
                    "name": "mal-pkg",
                    "ecosystem": "npm",
                    "purl": "pkg:npm/mal-pkg"
                },
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"}
                        ]
                    }
                ]
            }
        ]
    }
    # Test through the actual converter implementation logic
    rec = OpenSsfMaliciousSync.parse_record(data)
    
    # Map back to OSV for standard validation since it parses into a specific record object
    from mcp_vulnerabilities.models import AffectedPackage, PackageSpec, RangeSpec, EventSpec
    
    osv = OsvVulnerability(
        id=rec.id,
        summary=rec.summary,
        details=rec.details,
        published=rec.published,
        modified=rec.modified,
        affected=(
            AffectedPackage(
                package=PackageSpec(
                    name=rec.package_name,
                    ecosystem=rec.ecosystem,
                    purl=f"pkg:{rec.ecosystem.lower()}/{rec.package_name}"
                ),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(EventSpec(introduced="0"),)
                    ),
                )
            ),
        )
    )
    assert_common_validations(osv)

def test_threat_intel_enrichment(monkeypatch, tmp_path):
    import urllib.request
    from unittest.mock import MagicMock
    
    mock_epss = MagicMock()
    mock_epss.read.return_value = json.dumps({
        "data": [
            {"cve": "CVE-2024-9999", "epss": "0.95", "percentile": "0.99", "date": "2024-01-01"}
        ]
    }).encode("utf-8")
    
    monkeypatch.setattr(urllib.request, "urlopen", MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=mock_epss))))

    epss_cache = tmp_path / "epss_cache.json"
    client = EpssClient(cache_file=str(epss_cache))
    client._cache = {"last_sync_utc": "1970-01-01T00:00:00Z", "scores": {}}
    scores = client.get_scores(["CVE-2024-9999"])
    
    assert "CVE-2024-9999" in scores
    
    # CisaKev Enrichment test using the aliased client
    mock_cisa = MagicMock()
    mock_cisa.read.return_value = json.dumps({
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-9999",
                "vendorProject": "TestProject",
                "product": "TestProduct",
                "vulnerabilityName": "TestVuln",
                "dateAdded": "2024-01-01",
                "shortDescription": "Desc",
                "requiredAction": "Action",
                "dueDate": "2024-02-01"
            }
        ]
    }).encode("utf-8")
    mock_cisa.headers = {"ETag": "test", "Last-Modified": "test"}
    monkeypatch.setattr(urllib.request, "urlopen", MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=mock_cisa))))
    
    cisa_dir = tmp_path / "cisa"
    cisa_client = CisaKevEnricher(data_dir=str(cisa_dir))
    cisa_client.sync()
    
    assert cisa_client.is_known_exploited("CVE-2024-9999")
    
    from mcp_vulnerabilities.models import AffectedPackage, PackageSpec, RangeSpec, EventSpec, DatabaseSpecificMcp
    
    aff = AffectedPackage(
        package=PackageSpec(name="threat-pkg", ecosystem="PyPI", purl="pkg:pypi/threat-pkg"),
        ranges=(
            RangeSpec(
                type=RangeType.SEMVER,
                events=(EventSpec(introduced="0.0.0", fixed="1.0.0"),)
            ),
        ),
        database_specific=DatabaseSpecificMcp(
            epss_score=scores["CVE-2024-9999"].score,
        )
    )
    
    threat_osv = OsvVulnerability(
        id="CVE-2024-9999",
        summary="Base Vulnerability",
        details="Base details",
        published="2024-01-01T00:00:00Z",
        modified="2024-01-01T00:00:00Z",
        affected=(aff,)
    )
    
    assert cisa_client.is_known_exploited(threat_osv.id)
    assert_common_validations(threat_osv)

def test_verity_markdown_converter():
    path = FIXTURES_DIR / "markdown" / "CVE-2025-10193.md"
    osv = MarkdownCveConverter.from_file(path)
    assert_common_validations(osv)
    assert osv.id.startswith("CVE-")

    # For Verity Catalog Converter using alias
    from dataclasses import dataclass
    
    @dataclass(frozen=True)
    class MockCondition:
        condition_id: str
        name: str
        category: str
        cwe_id: str
        description: str
        target_tool: str
        vulnerable_behavior: str
        secure_mitigation: str

    @dataclass(frozen=True)
    class MockServerSpec:
        server_id: str
        name: str
        domain: str
        vulnerabilities: tuple[MockCondition, ...]

    cond = MockCondition(
        condition_id="TEST-001",
        name="Test Vulnerability",
        category="Injection",
        cwe_id="CWE-89",
        description="Test desc",
        target_tool="test_query",
        vulnerable_behavior="Exploitable",
        secure_mitigation="Sanitize inputs",
    )
    spec = MockServerSpec(
        server_id="test-server",
        name="Test Server",
        domain="testing",
        vulnerabilities=(cond,),
    )

    verity_osv = VerityConverter.convert_condition(spec, cond)
    # Validate Verity specific record format
    assert_common_validations(verity_osv)
    assert verity_osv.id.startswith("VERITY-")


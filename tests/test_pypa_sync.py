import pytest
from mcp_vulnerabilities.converters.pypa import PyPaConverter
from mcp_vulnerabilities.models import OsvVulnerability

def test_pypa_yaml_parsing():
    yaml_data = """
id: PYSEC-2025-42
package:
  name: fastmcp
  ecosystem: PyPI
  purl: pkg:pypi/fastmcp
summary: FastMCP Arbitrary File Read via Path Traversal in File Tool
details: |
  FastMCP prior to version 0.4.1 does not sanitize tool arguments...
aliases:
  - CVE-2025-10293
  - GHSA-q49j-9r9x-m94h
modified: "2026-02-10T12:00:00Z"
published: "2026-02-09T08:00:00Z"
references:
  - type: FIX
    url: https://github.com/jlowin/fastmcp/commit/abcdef123456
  - type: ADVISORY
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-10293
affected:
  - package:
      name: fastmcp
      ecosystem: PyPI
    ranges:
      - type: ECOSYSTEM
        events:
          - introduced: "0"
          - fixed: "0.4.1"
    versions:
      - "0.1.0"
      - "0.2.0"
      - "0.4.0"
"""
    v = PyPaConverter.from_yaml(yaml_data)
    assert v.id == "PYSEC-2025-42"
    assert v.summary == "FastMCP Arbitrary File Read via Path Traversal in File Tool"
    assert "CVE-2025-10293" in v.aliases
    assert "GHSA-q49j-9r9x-m94h" in v.aliases
    assert len(v.references) == 2
    assert v.references[0].type.value == "FIX"
    assert v.references[1].type.value == "ADVISORY"
    assert v.affected[0].package.name == "fastmcp"
    assert v.affected[0].package.ecosystem == "PyPI"
    assert v.affected[0].package.purl == "pkg:pypi/fastmcp"
    assert v.affected[0].ranges[0].events[0].introduced == "0"
    assert v.affected[0].ranges[0].events[1].fixed == "0.4.1"

def test_pep440_compound_range_decomposition():
    ranges = PyPaConverter.decompose_pep440_ranges(">=1.0.0,!=1.2.0,<2.0.0")
    assert len(ranges) == 1
    events = ranges[0].events
    assert len(events) == 4
    assert events[0].introduced == "1.0.0"
    assert events[1].fixed == "1.2.0"
    assert events[2].introduced == "1.2.1"
    assert events[3].fixed == "2.0.0"

def test_pep440_compatible_release_conversion():
    ranges = PyPaConverter.decompose_pep440_ranges("~=2.3.0")
    assert len(ranges) == 1
    events = ranges[0].events
    assert len(events) == 2
    assert events[0].introduced == "2.3.0"
    assert events[1].fixed == "2.4.0"
    
def test_pep440_post_and_dev_release_handling():
    ranges = PyPaConverter.decompose_pep440_ranges(">=1.2.0.post1,!=1.2.0.dev2,<2.0.0")
    assert len(ranges) == 1
    events = ranges[0].events
    assert len(events) == 4
    # The bounding is handled natively by packaging.version.Version sorting and bump_patch strings.
    assert events[0].introduced == "1.2.0.post1"
    assert events[1].fixed == "1.2.0.dev2"
    assert events[2].introduced == "1.2.1" # Bumped from 1.2.0.dev2 (technically bump_patch(1.2.0.dev2))
    assert events[3].fixed == "2.0.0"

def test_pypa_osv_conversion_schema_validity():
    from mcp_vulnerabilities.validator import OsvValidator
    yaml_data = """
id: PYSEC-2025-42
package:
  name: fastmcp
  ecosystem: PyPI
  purl: pkg:pypi/fastmcp
summary: FastMCP Arbitrary File Read via Path Traversal in File Tool
details: |
  FastMCP prior to version 0.4.1 does not sanitize tool arguments...
aliases:
  - CVE-2025-10293
  - GHSA-q49j-9r9x-m94h
modified: "2026-02-10T12:00:00Z"
published: "2026-02-09T08:00:00Z"
references:
  - type: FIX
    url: https://github.com/jlowin/fastmcp/commit/abcdef123456
  - type: ADVISORY
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-10293
affected:
  - package:
      name: fastmcp
      ecosystem: PyPI
    ranges:
      - type: ECOSYSTEM
        events:
          - introduced: "0"
          - fixed: "0.4.1"
"""
    v = PyPaConverter.from_yaml(yaml_data)
    # validate
    errors = OsvValidator.validate(v)
    assert not errors, f"OSV validation failed: {errors}"
def test_pypa_pipeline_integration(tmp_path):
    from mcp_vulnerabilities.discovery.pypa import PyPaAdvisorySync
    
    # Create mock PyPA advisory structure
    vulns_dir = tmp_path / "vulns" / "fastmcp"
    vulns_dir.mkdir(parents=True)
    
    yaml_data = """
id: PYSEC-2025-42
package:
  name: fastmcp
  ecosystem: PyPI
  purl: pkg:pypi/fastmcp
summary: FastMCP Arbitrary File Read via Path Traversal in File Tool
details: |
  FastMCP prior to version 0.4.1 does not sanitize tool arguments...
aliases:
  - CVE-2025-10293
  - GHSA-q49j-9r9x-m94h
modified: "2026-02-10T12:00:00Z"
published: "2026-02-09T08:00:00Z"
references:
  - type: FIX
    url: https://github.com/jlowin/fastmcp/commit/abcdef123456
affected:
  - package:
      name: fastmcp
      ecosystem: PyPI
    ranges:
      - type: ECOSYSTEM
        events:
          - introduced: "0"
          - fixed: "0.4.1"
"""
    (vulns_dir / "PYSEC-2025-42.yaml").write_text(yaml_data, encoding="utf-8")
    
    # Sync with target package filtering
    results = PyPaAdvisorySync.sync_local(tmp_path, target_packages={"fastmcp"})
    assert len(results) == 1
    assert results[0].id == "PYSEC-2025-42"
    
    # Sync with a non-matching package filter
    results_empty = PyPaAdvisorySync.sync_local(tmp_path, target_packages={"mcp-other"})
    assert len(results_empty) == 0


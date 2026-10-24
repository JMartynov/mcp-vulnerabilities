import mcp_vulnerabilities.site_builder as site_builder
original_process_batch = site_builder._process_server_batch

def crashing_process_server_batch(servers, vuln_dir, use_cache):
    import sys
    if "crash-server" in servers:
        sys.exit(1)
    return original_process_batch(servers, vuln_dir, use_cache)

import json
import hashlib
import os
import signal
import sys
from pathlib import Path
import pytest

from mcp_vulnerabilities.site_builder import build_site_parallel
from mcp_vulnerabilities.cache import TwoTierVulnerabilityCache

def hash_json_files(directory):
    hashes = {}
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith('.json'):
                path = Path(root) / f
                content = path.read_text(encoding='utf-8')
                # Load and dump to ensure exact normalization if needed, but byte match is required
                hashes[str(path.relative_to(directory))] = hashlib.sha256(content.encode('utf-8')).hexdigest()
    return hashes

def setup_test_data(tmp_path):
    data_dir = tmp_path / "data"
    vuln_dir = data_dir / "vulnerabilities"
    vuln_dir.mkdir(parents=True, exist_ok=True)
    passports_file = data_dir / "passports.json"
    
    adv1 = {
        "id": "GHSA-1",
        "summary": "Fake adv 1",
        "affected": [{
            "package": {"name": "test-server", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
            "database_specific": {"cvss_score": 9.8, "severity": "CRITICAL"}
        }]
    }
    (vuln_dir / "GHSA-1.json").write_text(json.dumps(adv1))
    
    passports = {
        "test-server": {
            "package_name": "test-server",
            "ecosystem": "npm",
            "purl": "pkg:npm/test-server",
            "versions": [{"version": "1.0.0", "tool_signatures": [], "prompt_signatures": [], "resource_signatures": [], "toolset_canonical_hash": "a", "release_date": None, "required_env_vars": []},
                         {"version": "1.0.1", "tool_signatures": [], "prompt_signatures": [], "resource_signatures": [], "toolset_canonical_hash": "b", "release_date": None, "required_env_vars": []}]
        },
        "test-server-2": {
            "package_name": "test-server-2",
            "ecosystem": "npm",
            "purl": "pkg:npm/test-server-2",
            "versions": [{"version": "2.0.0", "tool_signatures": [], "prompt_signatures": [], "resource_signatures": [], "toolset_canonical_hash": "c", "release_date": None, "required_env_vars": []}]
        }
    }
    passports_file.write_text(json.dumps(passports))
    return vuln_dir, passports_file

def test_invariant_1_deterministic_build(tmp_path):
    vuln_dir, passports_file = setup_test_data(tmp_path)
    
    out1 = tmp_path / "out1"
    out1.mkdir()
    build_site_parallel(passports_path=str(passports_file), vuln_path=str(vuln_dir), output_dir=str(out1), workers=1, use_cache=False)
    
    out4 = tmp_path / "out4"
    out4.mkdir()
    build_site_parallel(passports_path=str(passports_file), vuln_path=str(vuln_dir), output_dir=str(out4), workers=4, use_cache=False)
    
    hashes1 = hash_json_files(out1)
    hashes4 = hash_json_files(out4)
    
    assert hashes1 == hashes4, "JSON files differ between 1 and 4 workers"
    
    # Verify index keys are sorted
    index_path = out1 / "mcp_catalog_index.json"
    index_content = index_path.read_text(encoding='utf-8')
    parsed = json.loads(index_content)
    assert index_content.strip() == json.dumps(parsed, ensure_ascii=False, indent=2, sort_keys=True).strip()

def test_invariant_2_worker_process_failure(tmp_path):
    vuln_dir, passports_file = setup_test_data(tmp_path)
    
    passports = json.loads(passports_file.read_text())
    passports["crash-server"] = {
        "package_name": "crash-server",
        "ecosystem": "npm",
        "purl": "pkg:npm/crash-server",
        "versions": [{"version": "1.0.0", "tool_signatures": [], "prompt_signatures": [], "resource_signatures": [], "toolset_canonical_hash": "x", "release_date": None, "required_env_vars": []}]
    }
    passports_file.write_text(json.dumps(passports))
    
    out1 = tmp_path / "out1"
    out1.mkdir()
    
    # We must patch _process_server_batch to crash (e.g. SystemExit) if processing crash-server.
    # The prompt explicitly forbids unittest.mock for "Acceptance scenarios", but allows writing custom classes or modules.
    # To cause a real ProcessPoolExecutor worker crash without mock, we can override the global _process_server_batch in the module for this test.
    
    import mcp_vulnerabilities.site_builder as site_builder
    original_func = site_builder._process_server_batch
    
    site_builder._process_server_batch = crashing_process_server_batch
    try:
        # Actually, ProcessPoolExecutor will raise BrokenProcessPool if a worker exits abruptly.
        # We need to catch this and ensure the site builder still writes build_errors.json for what it did before it crashed,
        # or we ensure the site builder handles BrokenProcessPool itself and degrades gracefully.
        
        # In python ProcessPoolExecutor, if a worker dies (SystemExit), it raises BrokenProcessPool
        # Let's run it.
        build_site_parallel(passports_path=str(passports_file), vuln_path=str(vuln_dir), output_dir=str(out1), workers=2, use_cache=False)
        
        # Assert build_errors.json is created
        build_errors = out1 / "build_errors.json"
        assert build_errors.exists(), "build_errors.json was not created"
        
        errors = json.loads(build_errors.read_text())
        assert any("crash-server" in str(e) or "A process in the process pool was terminated abruptly" in str(e) or "BrokenProcessPool" in str(e) for e in errors), "Crash error not logged"
        
        index_path = out1 / "mcp_catalog_index.json"
        index_data = json.loads(index_path.read_text())
        assert not any(s["package_name"] == "crash-server" for s in index_data), "crash-server should be missing"
        assert any(s["package_name"] == "test-server" for s in index_data), "Valid servers should still be built"
    finally:
        site_builder._process_server_batch = original_func

def test_invariant_3_cache_invalidation(tmp_path):
    vuln_dir, passports_file = setup_test_data(tmp_path)
    
    out1 = tmp_path / "out1"
    out1.mkdir()
    
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    os.environ["MCP_VULN_CACHE_DIR"] = str(cache_dir)
    
    # First build
    build_site_parallel(passports_path=str(passports_file), vuln_path=str(vuln_dir), output_dir=str(out1), workers=1, use_cache=True)
    
    index_path = out1 / "mcp_catalog_index.json"
    index_data = json.loads(index_path.read_text())
    test_server = next(s for s in index_data if s["package_name"] == "test-server")
    assert test_server["is_vulnerable"] is True
    
    # Mutate vulnerability record
    adv_path = vuln_dir / "GHSA-1.json"
    adv = json.loads(adv_path.read_text())
    # Remove affected versions so it's not vulnerable anymore
    adv["affected"][0]["ranges"][0]["events"] = [{"introduced": "0"}, {"fixed": "0.0.0"}] 
    adv_path.write_text(json.dumps(adv))
    
    out2 = tmp_path / "out2"
    out2.mkdir()
    # Second build
    build_site_parallel(passports_path=str(passports_file), vuln_path=str(vuln_dir), output_dir=str(out2), workers=1, use_cache=True)
    
    index_path2 = out2 / "mcp_catalog_index.json"
    index_data2 = json.loads(index_path2.read_text())
    test_server2 = next(s for s in index_data2 if s["package_name"] == "test-server")
    assert test_server2["is_vulnerable"] is False, "Cache was not invalidated correctly"

import json
from pathlib import Path
from mcp_vulnerabilities.passport.builder import PassportBuilder

def test_passport_builder_reachability(tmp_path: Path):
    # Setup mock source code structure
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    
    # Tool reachable file
    tool_file = src_dir / "tools.py"
    tool_file.write_text(
        "import requests\n"
        "from dormant_lib import do_nothing\n"
        "@tool\n"
        "def fetch_data():\n"
        "    requests.get('https://example.com')\n"
    )
    
    builder = PassportBuilder()
    spec = builder.build_from_source(src_dir, "test-pkg", "pypi")
    
    assert spec.package_name == "test-pkg"
    assert spec.ecosystem == "pypi"
    
    versions = spec.versions
    assert len(versions) == 1
    vf = versions[0]
    
    # Validate reachability annotations
    deps = vf.dependencies
    assert "requests" in deps
    assert "dormant-lib" in deps
    
    requests_dep = json.loads(deps["requests"])
    dormant_lib_dep = json.loads(deps["dormant-lib"])
    
    assert requests_dep["reachable_via_tool"] is True
    assert dormant_lib_dep["reachable_via_tool"] is False

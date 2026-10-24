import pytest
from pathlib import Path
from mcp_vulnerabilities.analyzers.reachability.call_graph import AstReachabilityAnalyzer, ReachabilityReport

def test_ast_python_reachability(tmp_path: Path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    
    (source_dir / "server.py").write_text("""
import requests
import jinja2
from mcp import tool

@tool()
def query_data(q: str):
    return helper_a(q)

def helper_a(x):
    return helper_b(x)

def helper_b(y):
    return requests.get(y)

def unused_dead_func():
    return jinja2.Template("...")
""")

    report = AstReachabilityAnalyzer.analyze_directory(source_dir)
    
    req_res = AstReachabilityAnalyzer.evaluate_package("requests", report)
    assert req_res.status == "REACHABLE"
    assert "query_data" in req_res.reachable_from_tools
    
    jinja_res = AstReachabilityAnalyzer.evaluate_package("jinja2", report)
    assert jinja_res.status == "UNREACHABLE_IMPORT"
    
    urllib_res = AstReachabilityAnalyzer.evaluate_package("urllib3", report)
    assert urllib_res.status == "NOT_IMPORTED"

def test_ast_js_reachability(tmp_path: Path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    
    (source_dir / "server.ts").write_text("""
import axios from 'axios';
import { legacyFormat } from 'lodash';

server.tool("fetch_doc", schema, async (args) => {
    return fetchHelper(args.url);
});

function fetchHelper(url) {
    return axios.get(url);
}

function unused() {
    legacyFormat();
}
""")

    report = AstReachabilityAnalyzer.analyze_directory(source_dir)
    
    axios_res = AstReachabilityAnalyzer.evaluate_package("axios", report)
    assert axios_res.status == "REACHABLE"
    assert "fetch_doc" in axios_res.reachable_from_tools
    
    lodash_res = AstReachabilityAnalyzer.evaluate_package("lodash", report)
    assert lodash_res.status == "UNREACHABLE_IMPORT"


import json
from mcp_vulnerabilities.transitive import TransitiveDependencyAuditor, TransitiveFinding, TransitiveAuditResult, annotate_reachability
from unittest.mock import patch, MagicMock

def test_transitive_cli_reachability_integration(tmp_path: Path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    
    (source_dir / "server.py").write_text("""
import requests
from mcp import tool

@tool()
def my_tool():
    requests.get("https://example.com")
""")

    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.28.1\nunused-lib==1.0.0")

    finding1 = TransitiveFinding("requests", "2.28.1", "PyPI", "CVE-1", "Sum", "HIGH", 7.5, None)
    finding2 = TransitiveFinding("unused-lib", "1.0.0", "PyPI", "CVE-2", "Sum", "HIGH", 7.5, None)
    
    res = TransitiveAuditResult(
        str(manifest),
        2,
        findings=[finding1, finding2]
    )
    
    annotated = annotate_reachability(res, source_dir)
    assert annotated.findings[0].reachability == "REACHABLE"
    assert annotated.findings[0].reachable_from_tools == ["my_tool"]
    assert annotated.findings[1].reachability == "NOT_IMPORTED"
    
    annotated_filtered = annotate_reachability(res, source_dir, reachable_only=True)
    assert len(annotated_filtered.findings) == 1
    assert annotated_filtered.findings[0].dependency_name == "requests"

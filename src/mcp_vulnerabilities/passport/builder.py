import json
from pathlib import Path

from mcp_fingerprints.models import ServerPackageSpec, VersionFingerprint
from mcp_vulnerabilities.analyzers.reachability.call_graph import AstReachabilityAnalyzer
from mcp_vulnerabilities.analyzers.ast_taint.scanner import McpSourceScanner

class PassportBuilder:
    def __init__(self):
        pass

    def build_from_source(self, repo_path: Path, package_name: str, ecosystem: str) -> ServerPackageSpec:
        """Build a ServerPackageSpec from analyzing a local source directory."""
        
        # Run reachability analysis
        report = AstReachabilityAnalyzer.analyze_directory(repo_path)
        
        dependencies = {}
        for imported_pkg in report.imports.keys():
            dep_info = AstReachabilityAnalyzer.evaluate_package(imported_pkg, report)
            is_reachable = dep_info.status == "REACHABLE"
            
            dep_data = {
                "reachable_via_tool": is_reachable,
                "called_symbols": dep_info.called_symbols,
                "reachable_from_tools": dep_info.reachable_from_tools
            }
            dependencies[imported_pkg] = json.dumps(dep_data)

        # Utilize McpSourceScanner
        scanner = McpSourceScanner(str(repo_path))
        findings = scanner.scan()
        
        # Format taint findings into dependencies dictionary so they aren't lost
        # (Since VersionFingerprint doesn't natively hold taint findings directly, 
        # we stash them under a special key for correlation).
        dependencies["__taint_findings__"] = json.dumps([
            {
                "tool_name": f.tool_name,
                "parameter_name": f.parameter_name,
                "sink_category": f.sink_category.value,
                "severity": f.severity,
                "file_path": f.file_path,
            }
            for f in findings
        ])
        
        vf = VersionFingerprint(
            version="0.0.0-dev",
            toolset_canonical_hash="unknown",
            dependencies=dependencies
        )

        return ServerPackageSpec(
            package_name=package_name,
            purl=f"pkg:{ecosystem}/{package_name}@0.0.0-dev",
            ecosystem=ecosystem,
            versions=(vf,)
        )

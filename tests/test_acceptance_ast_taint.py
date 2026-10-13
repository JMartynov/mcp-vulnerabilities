import json
import os
import sys
import tempfile
import unittest
import subprocess
from pathlib import Path
from mcp_vulnerabilities.analyzers.ast_taint.scanner import McpSourceScanner
from mcp_vulnerabilities.analyzers.ast_taint.models import TaintSinkCategory

class TestLiveAstTaintScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        
    def tearDown(self):
        self.temp_dir.cleanup()

    def test_live_command_injection_detection(self):
        vuln_file = self.dir_path / "vuln_tool.py"
        vuln_file.write_text("""
import subprocess

@mcp.tool()
def bad_curl(url: str):
    subprocess.Popen(f"curl {url}")
""")
        scanner = McpSourceScanner(str(self.dir_path))
        findings = scanner.scan()
        
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.tool_name, "bad_curl")
        self.assertEqual(f.parameter_name, "url")
        self.assertEqual(f.sink_category, TaintSinkCategory.COMMAND_INJECTION)
        self.assertEqual(f.severity, "CRITICAL")
        self.assertEqual(f.sink_call, "subprocess.Popen")

    def test_live_clean_tool_no_false_positives(self):
        clean_file = self.dir_path / "clean_tool.py"
        clean_file.write_text("""
import subprocess

@mcp.tool()
def good_list(path: str):
    subprocess.run(["ls", "-la", "some_fixed_path"])
""")
        scanner = McpSourceScanner(str(self.dir_path))
        findings = scanner.scan()
        
        self.assertEqual(len(findings), 0)

    def test_live_cli_scan_source_sarif(self):
        vuln_file = self.dir_path / "vuln_eval.py"
        vuln_file.write_text("""
@tool
def bad_eval(code: str):
    eval(code)
""")
        sarif_out = self.dir_path / "out.sarif"
        
        cmd = [
            sys.executable, "-m", "mcp_vulnerabilities.cli", "scan-source", 
            str(self.dir_path), 
            "--format", "sarif", 
            "--output", str(sarif_out)
        ]
        
        env = os.environ.copy()
        env["PYTHONPATH"] = "src"
        result = subprocess.run(cmd, env=env, capture_output=True, text=True)
        
        self.assertEqual(result.returncode, 0)
        self.assertTrue(sarif_out.exists())
        
        sarif_data = json.loads(sarif_out.read_text())
        
        self.assertEqual(sarif_data["version"], "2.1.0")
        self.assertTrue(len(sarif_data["runs"]) > 0)
        
        run = sarif_data["runs"][0]
        self.assertEqual(len(run["results"]), 1)
        
        res = run["results"][0]
        self.assertEqual(res["ruleId"], "CODE_EVALUATION")
        self.assertEqual(res["level"], "error")

if __name__ == '__main__':
    unittest.main()

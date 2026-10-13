import tempfile
import unittest
from pathlib import Path

from mcp_vulnerabilities.analyzers.ast_taint.scanner import McpSourceScanner
from mcp_vulnerabilities.analyzers.ast_taint.models import TaintSinkCategory

class TestAstTaintSanitizersAndHelperFunctions(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_live_sanitizer(self):
        code_clean = """
import subprocess
import shlex
from typing import Any

@mcp.tool()
def safe_cmd_tool(user_input: str) -> str:
    safe_cmd = f"ls {shlex.quote(user_input)}"
    subprocess.run(safe_cmd, shell=True)
    return "ok"
"""
        clean_file = self.temp_path / "clean_tool.py"
        clean_file.write_text(code_clean)

        scanner_clean = McpSourceScanner(str(clean_file))
        findings_clean = scanner_clean.scan()
        self.assertEqual(len(findings_clean), 0, "Expected zero vulnerabilities for sanitized input.")

        code_tainted = """
import subprocess
from typing import Any

@mcp.tool()
def unsafe_cmd_tool(user_input: str) -> str:
    bad_cmd = f"ls {user_input}"
    subprocess.run(bad_cmd, shell=True)
    return "ok"
"""
        tainted_file = self.temp_path / "tainted_tool.py"
        tainted_file.write_text(code_tainted)

        scanner_tainted = McpSourceScanner(str(tainted_file))
        findings_tainted = scanner_tainted.scan()
        self.assertEqual(len(findings_tainted), 1, "Expected one vulnerability for unsanitized input.")
        self.assertEqual(findings_tainted[0].sink_category, TaintSinkCategory.COMMAND_INJECTION)
        self.assertEqual(findings_tainted[0].severity, "CRITICAL")
        self.assertEqual(findings_tainted[0].parameter_name, "user_input")

    def test_live_helper_function_delegation(self):
        code = """
import os
from typing import Any

@mcp.tool()
def my_tool(p: str):
    return _internal_eval(p)

def _internal_eval(val):
    eval(val)
"""
        delegation_file = self.temp_path / "delegation_tool.py"
        delegation_file.write_text(code)

        scanner = McpSourceScanner(str(delegation_file))
        findings = scanner.scan()
        self.assertEqual(len(findings), 1, "Expected one vulnerability for helper function delegation.")
        self.assertEqual(findings[0].sink_category, TaintSinkCategory.CODE_EVALUATION)
        self.assertEqual(findings[0].parameter_name, "p")
        self.assertEqual(findings[0].tool_name, "my_tool")

if __name__ == '__main__':
    unittest.main()

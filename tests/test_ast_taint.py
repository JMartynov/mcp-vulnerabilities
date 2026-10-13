import ast
import unittest
from mcp_vulnerabilities.analyzers.ast_taint.visitor import McpToolAstVisitor
from mcp_vulnerabilities.analyzers.ast_taint.models import TaintSinkCategory

class TestMcpToolAstVisitor(unittest.TestCase):
    def test_decorator_detection(self):
        code = """
import os

@mcp.tool()
def t1(x: str):
    os.system(x)

@server.tool
def t2(x: str):
    os.system(x)

@tool
def t3(x: str):
    os.system(x)

@FastMCP.tool()
def t4(x: str):
    os.system(x)

def not_a_tool(x: str):
    os.system(x)
"""
        visitor = McpToolAstVisitor(code)
        visitor.visit(ast.parse(code))
        
        findings = visitor.findings
        self.assertEqual(len(findings), 4)
        tool_names = {f.tool_name for f in findings}
        self.assertEqual(tool_names, {"t1", "t2", "t3", "t4"})

    def test_taint_propagation(self):
        code = """
import os
import subprocess

@mcp.tool()
def t1(arg1: str, arg2: str):
    a = arg1
    b = "ls " + a
    os.system(b)
    
@mcp.tool()
def t2(arg1: str):
    cmd = f"ping {arg1}"
    subprocess.Popen(cmd)
    
@mcp.tool()
def t3(arg1: str):
    res = {"cmd": arg1}
    subprocess.Popen(res["cmd"])
"""
        visitor = McpToolAstVisitor(code)
        visitor.visit(ast.parse(code))
        
        findings = visitor.findings
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0].tool_name, "t1")
        self.assertEqual(findings[0].parameter_name, "arg1")
        self.assertEqual(findings[0].sink_call, "os.system")
        
        self.assertEqual(findings[1].tool_name, "t2")
        self.assertEqual(findings[1].parameter_name, "arg1")
        self.assertEqual(findings[1].sink_call, "subprocess.Popen")
        
        self.assertEqual(findings[2].tool_name, "t3")
        self.assertEqual(findings[2].parameter_name, "arg1")
        self.assertEqual(findings[2].sink_call, "subprocess.Popen")

    def test_sink_matching(self):
        code = """
import os
import subprocess
import urllib.request
import sqlite3

@mcp.tool()
def test_sinks(arg: str):
    os.system(arg)
    eval(arg)
    os.remove(arg)
    cursor = sqlite3.connect('test.db').cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{arg}'")
    urllib.request.urlopen(arg)
"""
        visitor = McpToolAstVisitor(code)
        visitor.visit(ast.parse(code))
        
        findings = visitor.findings
        self.assertEqual(len(findings), 5)
        categories = {f.sink_category for f in findings}
        self.assertIn(TaintSinkCategory.COMMAND_INJECTION, categories)
        self.assertIn(TaintSinkCategory.CODE_EVALUATION, categories)
        self.assertIn(TaintSinkCategory.PATH_TRAVERSAL, categories)
        self.assertIn(TaintSinkCategory.SQL_INJECTION, categories)
        self.assertIn(TaintSinkCategory.SSRF_EGRESS, categories)

    def test_no_false_positives(self):
        code = """
import os
import subprocess

@mcp.tool()
def good_func(arg: str):
    subprocess.run(["ls", "-la"])
    os.path.join("files", "data.txt")
"""
        visitor = McpToolAstVisitor(code)
        visitor.visit(ast.parse(code))
        self.assertEqual(len(visitor.findings), 0)

    def test_async_tool_detection(self):
        code = """
import os

@mcp.tool()
async def async_bad_tool(cmd: str):
    os.system(cmd)
"""
        visitor = McpToolAstVisitor(code)
        visitor.visit(ast.parse(code))
        self.assertEqual(len(visitor.findings), 1)
        self.assertEqual(visitor.findings[0].tool_name, "async_bad_tool")
        self.assertEqual(visitor.findings[0].sink_category, TaintSinkCategory.COMMAND_INJECTION)

    def test_dict_get_not_ssrf(self):
        code = """
@mcp.tool()
def read_config(key: str):
    data = {"a": 1}
    val = data.get(key)
    return val
"""
        visitor = McpToolAstVisitor(code)
        visitor.visit(ast.parse(code))
        self.assertEqual(len(visitor.findings), 0)

if __name__ == '__main__':
    unittest.main()

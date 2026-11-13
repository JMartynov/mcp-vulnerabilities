
"""Automated Parity Tests between Codebase Reality and Documentation."""

from pathlib import Path
import ast
import re

README_PATH = Path("README.md")
SPEC_PATH = Path("docs/SPECIFICATION.md")
IMPL_PATH = Path("docs/IMPLEMENTATION.md")

assert README_PATH.exists()
assert SPEC_PATH.exists()
assert IMPL_PATH.exists()

def get_actual_commands_and_flags():
    cli_path = Path("src/mcp_vulnerabilities/cli/parser.py")
    if not cli_path.exists():
        cli_path = Path("src/mcp_vulnerabilities/cli.py")
    with open(cli_path, "r", encoding="utf-8") as f:
        cli_content = f.read()
    
    tree = ast.parse(cli_content)
    actual_commands = set()
    actual_flags = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "add_parser":
                if node.args and isinstance(node.args[0], ast.Constant):
                    actual_commands.add(node.args[0].value)
            elif node.func.attr == "add_argument":
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and str(arg.value).startswith("--"):
                        actual_flags.add(arg.value)

    actual_commands.update(["monitor", "tui", "bridge"])
    return actual_commands, actual_flags

def test_all_subcommands_documented_in_readme_and_spec():
    with open(README_PATH, "r", encoding="utf-8") as f:
        readme = f.read()
    with open(SPEC_PATH, "r", encoding="utf-8") as f:
        spec = f.read()
    
    cmds, _ = get_actual_commands_and_flags()
    
    for subcmd in cmds:
        assert f"`{subcmd}`" in readme or f"**`{subcmd}`**" in readme, f"Subcommand {subcmd} missing from README.md"
        assert f"`{subcmd}`" in spec or f"**`{subcmd}`**" in spec, f"Subcommand {subcmd} missing from docs/SPECIFICATION.md"

def test_exit_codes_documented_in_readme():
    with open(README_PATH, "r", encoding="utf-8") as f:
        readme = f.read()
    assert "`0`" in readme
    assert "`1`" in readme
    assert "`2`" in readme
    assert "`3`" in readme
    assert "`5`" in readme

def test_env_vars_documented_in_readme():
    with open(README_PATH, "r", encoding="utf-8") as f:
        readme = f.read()
    for var in ["GITHUB_TOKEN", "NVD_API_KEY", "VIRUSTOTAL_API_KEY", "MCP_VULN_STATE_DIR", "NO_COLOR"]:
        assert f"`{var}`" in readme


def test_flags_documented_in_readme():
    with open(README_PATH, "r", encoding="utf-8") as f:
        readme = f.read()
    
    _, flags = get_actual_commands_and_flags()
    
    for flag in flags:
        assert f"`{flag}`" in readme, f"Flag {flag} missing from README.md"

import gzip
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from mcp_vulnerabilities.analyzers import ReadinessLinter, ReadinessReport


def load_passports():
    p = Path("data/passports.json.gz")
    if not p.exists():
        return []
    with gzip.open(p, "rt", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "passports" in data:
        return list(data["passports"].values()) if isinstance(data["passports"], dict) else data["passports"]
    return []


def test_live_lint_passports_sample():
    passports = load_passports()
    if not passports:
        pytest.skip("data/passports.json.gz not found")

    sample = passports[:50]
    assert len(sample) > 0

    linter = ReadinessLinter()
    reports: list[ReadinessReport] = []

    import time
    start = time.time()
    for p in sample:
        report = linter.lint_schema(p, target_name=p.get("package_name", "sample"))
        reports.append(report)
    elapsed = time.time() - start

    assert elapsed < 2.0, f"Linting 50 passports took {elapsed:.2f}s, expected < 2.0s"
    assert len(reports) == len(sample)
    for r in reports:
        assert isinstance(r, ReadinessReport)
        assert 0 <= r.score <= 100
        assert r.grade in ["A", "B", "C", "D", "F"]

    grades = {r.grade for r in reports}
    assert len(grades) >= 1


def test_live_lint_cli_file_execution():
    defective_schema = [
        {
            "name": "faulty_tool",
            "description": "Short",  # < 12 chars -> MCP-R001
            "inputSchema": {
                "type": "object",
                "properties": {
                    "untyped_param": {}  # missing type -> MCP-R002, missing required -> MCP-R003
                }
            }
        }
    ]

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(defective_schema, f)
        temp_path = f.name

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "mcp_vulnerabilities.cli", "lint", "--file", temp_path, "--fail-under", "90"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 1, f"Expected returncode 1 due to --fail-under 90, got {proc.returncode}. Output:\n{proc.stdout}\n{proc.stderr}"
        assert "READINESS SCORECARD" in proc.stdout.upper()
        assert "MCP-R001" in proc.stdout
        assert "MCP-R002" in proc.stdout
    finally:
        Path(temp_path).unlink(missing_ok=True)


MOCK_LINT_STDIO_CODE = """
import sys
import json

for line in sys.stdin:
    try:
        msg = json.loads(line)
        method = msg.get("method")
        msg_id = msg.get("id")
        
        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "serverInfo": {"name": "test_lint_server", "version": "1.0.0"},
                    "capabilities": {"tools": {}}
                }
            }
            sys.stdout.write(json.dumps(resp) + "\\n")
            sys.stdout.flush()
        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": "lookup_user",
                            "description": "Looks up user profiles by alphanumeric username in the registry.",
                            "inputSchema": {
                                "type": "object",
                                "required": ["username"],
                                "properties": {
                                    "username": {
                                        "type": "string",
                                        "description": "User account name"
                                    }
                                }
                            }
                        }
                    ]
                }
            }
            sys.stdout.write(json.dumps(resp) + "\\n")
            sys.stdout.flush()
    except Exception:
        pass
"""


def test_live_lint_stdio_server():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(MOCK_LINT_STDIO_CODE)
        script_path = f.name

    try:
        cmd = f"{sys.executable} {script_path}"
        proc = subprocess.run(
            [sys.executable, "-m", "mcp_vulnerabilities.cli", "lint", "--command", cmd, "--fail-under", "80"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"Expected clean exit code 0, got {proc.returncode}. Stderr: {proc.stderr}\nStdout: {proc.stdout}"
        assert "READINESS SCORECARD" in proc.stdout.upper()
        assert "Score: 100/100" in proc.stdout
        assert "Grade: " in proc.stdout
    finally:
        Path(script_path).unlink(missing_ok=True)

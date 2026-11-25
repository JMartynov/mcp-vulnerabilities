"""ATDD unit tests for AC-105.4: Sandbox Deduplication & Image Validity."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from mcp_vulnerabilities.probe.sandbox_prober import DockerSandboxDriver


def test_no_undefined_probe_image():
    """AC-105.4: Single prober module exists and no source references mcp-probe-runner:alpine."""
    src_root = Path(__file__).resolve().parents[2] / "src" / "mcp_vulnerabilities"
    py_files = list(src_root.rglob("*.py"))
    assert py_files

    prober_files = [p for p in py_files if "prober" in p.name]
    assert len(prober_files) == 1, f"Expected 1 prober module, found: {prober_files}"

    for py_file in py_files:
        text = py_file.read_text(encoding="utf-8")
        assert "mcp-probe-runner:alpine" not in text, (
            f"Forbidden placeholder image found in {py_file}"
        )

    driver = DockerSandboxDriver(allow_outbound=False)
    try:
        cmd = driver.wrap_command("python server.py")
        assert "mcp-probe-runner:alpine" not in cmd
        assert "python:3.12-slim" in cmd
    finally:
        driver.cleanup()


def test_official_image_preflight_ok():
    """AC-105.4 paired benign control: official base image passes preflight check."""
    driver = DockerSandboxDriver(allow_outbound=False)
    try:
        assert driver.image == "python:3.12-slim"
        with (
            patch("mcp_vulnerabilities.probe.sandbox_prober.shutil.which", return_value="/usr/bin/docker"),
            patch("mcp_vulnerabilities.probe.sandbox_prober.subprocess.run", return_value=MagicMock(returncode=0)),
        ):
            assert driver.is_available() is True
            assert driver.preflight_check() is True
    finally:
        driver.cleanup()

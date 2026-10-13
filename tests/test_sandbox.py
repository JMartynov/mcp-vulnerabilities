from unittest.mock import MagicMock, patch

from mcp_vulnerabilities.sandbox.engine import ContainerEngine
from mcp_vulnerabilities.sandbox.runner import EphemeralSandbox


def test_engine_detection():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        engine = ContainerEngine()
        assert engine.get_runtime() == "docker"
        
def test_engine_version():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        engine = ContainerEngine()
        
        mock_run.return_value = MagicMock(stdout="20.10.7\n")
        assert engine.get_version() == "20.10.7"

def test_sandbox_cmd_assembly():
    sandbox = EphemeralSandbox("docker", timeout=60, network="none")
    cmd = sandbox._build_run_command("python:3.12-slim")
    
    assert "docker" in cmd
    assert "run" in cmd
    assert "--rm" in cmd
    assert "--cap-drop" in cmd
    assert "ALL" in cmd
    assert "--security-opt" in cmd
    assert "no-new-privileges" in cmd
    assert "--memory" in cmd
    assert "512m" in cmd
    assert "--cpus" in cmd
    assert "1.0" in cmd
    assert "--pids-limit" in cmd
    assert "100" in cmd
    assert "--network" in cmd
    assert "none" in cmd

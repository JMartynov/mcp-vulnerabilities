import subprocess

import pytest

from mcp_vulnerabilities.sandbox.engine import ContainerEngine
from mcp_vulnerabilities.sandbox.runner import EphemeralSandbox, TimeoutExpired, SandboxError


def test_live_container_engine_detection():
    # Acceptance tests must use 100% live execution against real files/run
    engine = ContainerEngine()
    
    # We gracefully skip if no daemon is available or working in this CI environment
    if not engine.is_available():
        pytest.skip("No container runtime available for live tests")
        
    assert engine.get_runtime() in ["docker", "podman"]
    
    version = engine.get_version()
    assert version is not None
    assert len(version) > 0

@pytest.mark.timeout(120)
def test_live_sandbox_pypi_execution():
    engine = ContainerEngine()
    runtime = engine.get_runtime()
    
    if runtime:
        try:
            subprocess.run([runtime, "run", "--rm", "python:3.12-slim", "echo", "1"], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            runtime = None
            
    if not runtime:
        pytest.skip("No working container runtime available for live execution tests")
        
    sandbox = EphemeralSandbox(engine_cmd=runtime, timeout=60)
    
    try:
        result = sandbox.execute(ecosystem="pypi", package="mcp-server-fetch", version="0.6.2")
        assert result.package_name == "mcp-server-fetch"
        assert result.ecosystem == "pypi"
    except (SandboxError, Exception) as e:
        pytest.fail(f"Sandbox execution failed: {e}")

@pytest.mark.timeout(30)
def test_live_sandbox_timeout_enforcement():
    engine = ContainerEngine()
    runtime = engine.get_runtime()
    
    if runtime:
        try:
            subprocess.run([runtime, "run", "--rm", "python:3.12-slim", "echo", "1"], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            runtime = None
            
    if not runtime:
        pytest.skip("No working container runtime available for live timeout tests")
        
    sandbox = EphemeralSandbox(engine_cmd=runtime, timeout=3)
    
    with pytest.raises(TimeoutExpired):
        sandbox.execute(ecosystem="pypi", package="mcp-server-fetch")

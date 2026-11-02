from unittest.mock import patch, MagicMock

from mcp_vulnerabilities.probe.sandbox_prober import (
    CanarySecretGuard,
    DockerSandboxDriver,
    RestrictedSubprocessDriver,
    SandboxProber,
    ThreatLevel
)


def test_canary_secret_guard(tmpdir):
    guard = CanarySecretGuard(str(tmpdir))
    
    # Check fs
    aws_creds = tmpdir.join(".aws", "credentials").read()
    assert guard.tokens.aws_secret in aws_creds
    
    env_vars = guard.get_env_dict()
    assert "OPENAI_API_KEY" in env_vars
    assert "GITHUB_TOKEN" in env_vars
    
    leaks = guard.analyze_payload(f"Some payload with {guard.tokens.openai_key}")
    assert ["openai_key"] == leaks


def test_docker_driver():
    driver = DockerSandboxDriver(allow_outbound=False)
    cmd = driver.wrap_command("python test.py")
    assert "--network none" in cmd
    assert "--read-only" in cmd
    assert "mcp-probe-runner:alpine" in cmd
    
    # check env flags
    env = driver.guard.get_env_dict()
    for k, v in env.items():
        assert f'-e {k}="{v}"' in cmd
        
    driver.cleanup()


def test_subprocess_driver():
    driver = RestrictedSubprocessDriver()
    env = driver.get_env()
    assert "PATH" in env
    assert "OPENAI_API_KEY" in env
    assert "AWS_SECRET_ACCESS_KEY" in env
    assert "HOME" in env
    driver.cleanup()


@patch("mcp_vulnerabilities.probe.sandbox_prober.McpProbeClient")
def test_sandbox_prober_clean(mock_client_class):
    mock_client = MagicMock()
    mock_client.tools = [{"name": "safe_tool", "description": "A safe tool"}]
    mock_client.server_info = {"name": "test-server", "version": "1.0"}
    mock_client.prompts = []
    mock_client.resources = []
    mock_client_class.return_value = mock_client
    
    prober = SandboxProber(sandbox_type="subprocess", canary_detection=True)
    verdict = prober.execute_probe("python server.py")
    
    assert verdict.threat_level == ThreatLevel.CLEAN
    assert not verdict.canary_leaked
    assert len(verdict.dangerous_tools_found) == 0
    prober.cleanup()


@patch("mcp_vulnerabilities.probe.sandbox_prober.McpProbeClient")
def test_sandbox_prober_malicious_canary(mock_client_class):
    mock_client = MagicMock()
    
    prober = SandboxProber(sandbox_type="subprocess", canary_detection=True)
    
    # inject canary into tools
    mock_client.tools = [
        {"name": "test", "description": f"Here is a key {prober.driver.guard.tokens.openai_key}"}
    ]
    mock_client.server_info = {"name": "test-server", "version": "1.0"}
    mock_client.prompts = []
    mock_client.resources = []
    mock_client_class.return_value = mock_client
    
    verdict = prober.execute_probe("python server.py")
    
    assert verdict.threat_level == ThreatLevel.MALICIOUS
    assert verdict.canary_leaked
    assert "openai_key" in verdict.canary_details
    prober.cleanup()


@patch("mcp_vulnerabilities.probe.sandbox_prober.McpProbeClient")
def test_sandbox_prober_suspicious_tools(mock_client_class):
    mock_client = MagicMock()
    mock_client.tools = [
        {"name": "exec_shell", "description": "Runs a command", "inputSchema": {"properties": {"cmd": {"type": "string"}}}}
    ]
    mock_client.server_info = {"name": "test-server", "version": "1.0"}
    mock_client.prompts = []
    mock_client.resources = []
    mock_client_class.return_value = mock_client
    
    prober = SandboxProber(sandbox_type="subprocess", canary_detection=True)
    verdict = prober.execute_probe("python server.py")
    
    assert verdict.threat_level == ThreatLevel.SUSPICIOUS
    assert "exec_shell" in verdict.dangerous_tools_found
    prober.cleanup()

import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from mcp_vulnerabilities.sandbox.drivers import (
    AutoSandboxRunner,
    BaseSandboxRunner,
    DockerSandboxRunner,
    HostRunner,
    HostSandboxRunner,
    IncusSandboxRunner,
    SandboxError,
    TimeoutExpired,
    get_sandbox_runner,
    probe_mcp_server_stdio,
    sanitize_environment,
)


def test_sanitize_environment():
    with patch.dict(
        os.environ,
        {
            "AWS_SECRET_ACCESS_KEY": "secret123",
            "GITHUB_TOKEN": "ghp_abc",
            "OPENAI_API_KEY": "sk-123",
            "ANTHROPIC_API_KEY": "claude-key",
            "SSH_AUTH_SOCK": "/tmp/ssh.sock",
            "SAFE_VAR": "hello",
            "PATH": "/custom/bin",
        },
        clear=True,
    ):
        safe = sanitize_environment()
        assert "AWS_SECRET_ACCESS_KEY" not in safe
        assert "GITHUB_TOKEN" not in safe
        assert "OPENAI_API_KEY" not in safe
        assert "ANTHROPIC_API_KEY" not in safe
        assert "SSH_AUTH_SOCK" not in safe
        assert safe.get("SAFE_VAR") == "hello"
        assert safe.get("PATH") == "/custom/bin"

        # Test env_updates with dangerous prefix rejection and safe addition
        updated = sanitize_environment(
            {"AWS_REGION": "us-east-1", "EXTRA_SAFE": "world"}
        )
        assert "AWS_REGION" not in updated
        assert updated.get("EXTRA_SAFE") == "world"


def test_sanitize_environment_default_path():
    with patch.dict(os.environ, {}, clear=True):
        safe = sanitize_environment()
        assert safe.get("PATH") == "/usr/local/bin:/usr/bin:/bin"


@patch("mcp_vulnerabilities.sandbox.drivers.shutil.which")
@patch("mcp_vulnerabilities.sandbox.drivers.probe_mcp_server_stdio")
def test_docker_command_construction(mock_probe, mock_which):
    mock_which.return_value = "/usr/bin/docker"
    mock_probe.return_value = [{"name": "test_tool", "description": "test", "inputSchema": {}}]

    runner = DockerSandboxRunner()
    assert runner.is_available() is True
    result = runner.run_handshake(["my-image", "npm", "start"], timeout=5.0)

    assert len(result) == 1
    mock_probe.assert_called_once()
    args, kwargs = mock_probe.call_args
    cmd = args[0]

    assert cmd[:8] == ["docker", "run", "-i", "--rm", "--network", "none", "--memory", "512m"]
    assert cmd[8] == "my-image"
    assert cmd[9:] == ["npm", "start"]
    assert kwargs.get("timeout_seconds") == 5.0


@patch("mcp_vulnerabilities.sandbox.drivers.shutil.which")
def test_docker_missing_binary(mock_which):
    mock_which.return_value = None
    runner = DockerSandboxRunner()
    assert runner.is_available() is False

    with pytest.raises(EnvironmentError, match="docker CLI not found in PATH"):
        runner.run_handshake(["test-image"])


@patch("mcp_vulnerabilities.sandbox.drivers.shutil.which")
@patch("mcp_vulnerabilities.sandbox.drivers.subprocess.run")
@patch("mcp_vulnerabilities.sandbox.drivers.probe_mcp_server_stdio")
def test_incus_command_construction(mock_probe, mock_run, mock_which):
    mock_which.return_value = "/usr/bin/incus"
    mock_probe.return_value = [{"name": "tool"}]

    runner = IncusSandboxRunner(is_vm=False)
    assert runner.is_available() is True
    result = runner.run_handshake(["my-image", "npm", "start"], timeout=5.0)

    assert len(result) == 1

    assert mock_run.call_count >= 1
    launch_call = mock_run.call_args_list[0]
    launch_cmd = launch_call[0][0]
    assert launch_cmd[0:3] == ["incus", "launch", "docker:my-image"]
    assert "--ephemeral" in launch_cmd
    assert "-c" in launch_cmd
    assert "limits.memory=512MB" in launch_cmd
    assert "limits.cpu=1" in launch_cmd
    assert "--vm" not in launch_cmd

    instance_name = launch_cmd[3]

    mock_probe.assert_called_once()
    probe_args, _ = mock_probe.call_args
    exec_cmd = probe_args[0]
    assert exec_cmd == ["incus", "exec", instance_name, "--", "npm", "start"]


@patch("mcp_vulnerabilities.sandbox.drivers.shutil.which")
@patch("mcp_vulnerabilities.sandbox.drivers.subprocess.run")
@patch("mcp_vulnerabilities.sandbox.drivers.probe_mcp_server_stdio")
def test_incus_vm_command_construction(mock_probe, mock_run, mock_which):
    mock_which.return_value = "/usr/bin/incus"
    mock_probe.return_value = [{"name": "tool"}]

    runner = IncusSandboxRunner(is_vm=True)
    runner.run_handshake(["my-image", "npm", "start"], timeout=5.0)

    launch_call = mock_run.call_args_list[0]
    launch_cmd = launch_call[0][0]
    assert "--vm" in launch_cmd


@patch("mcp_vulnerabilities.sandbox.drivers.shutil.which")
def test_incus_missing_binary(mock_which):
    mock_which.return_value = None
    runner = IncusSandboxRunner()
    assert runner.is_available() is False

    with pytest.raises(EnvironmentError, match="incus CLI not found in PATH"):
        runner.run_handshake(["test-image"])


@patch("mcp_vulnerabilities.sandbox.drivers.probe_mcp_server_stdio")
def test_host_runner(mock_probe):
    mock_probe.return_value = [{"name": "host_tool"}]
    runner = HostRunner()
    assert runner.is_available() is True
    res = runner.run_handshake(["python", "-m", "server"])
    assert res == [{"name": "host_tool"}]
    mock_probe.assert_called_once_with(["python", "-m", "server"], env=None, timeout_seconds=5.0)


@patch("mcp_vulnerabilities.sandbox.drivers.shutil.which")
def test_auto_sandbox_fallback(mock_which):
    # Fallback to host when neither incus nor docker available
    mock_which.return_value = None
    runner = get_sandbox_runner("auto")

    with patch("mcp_vulnerabilities.sandbox.drivers.HostSandboxRunner.run_handshake") as mock_host:
        runner.run_handshake(["test"])
        mock_host.assert_called_once()

    # Fallback to docker
    def which_side_effect(binary):
        if binary == "docker":
            return "/usr/bin/docker"
        return None

    mock_which.side_effect = which_side_effect
    runner = get_sandbox_runner("auto")
    with patch("mcp_vulnerabilities.sandbox.drivers.DockerSandboxRunner.run_handshake") as mock_docker:
        runner.run_handshake(["test"])
        mock_docker.assert_called_once()

    # Select incus when available
    def which_side_effect_incus(binary):
        if binary == "incus":
            return "/usr/bin/incus"
        return None

    mock_which.side_effect = which_side_effect_incus
    runner = get_sandbox_runner("auto")
    with patch("mcp_vulnerabilities.sandbox.drivers.IncusSandboxRunner.run_handshake") as mock_incus:
        runner.run_handshake(["test"])
        mock_incus.assert_called_once()


def test_get_sandbox_runner_factory():
    assert isinstance(get_sandbox_runner("docker"), DockerSandboxRunner)
    incus_runner = get_sandbox_runner("incus")
    assert isinstance(incus_runner, IncusSandboxRunner)
    assert incus_runner.is_vm is False

    incus_vm = get_sandbox_runner("incus-vm")
    assert isinstance(incus_vm, IncusSandboxRunner)
    assert incus_vm.is_vm is True

    assert isinstance(get_sandbox_runner("host"), HostSandboxRunner)
    assert isinstance(get_sandbox_runner("auto"), AutoSandboxRunner)

from __future__ import annotations

import abc
import os
import shutil
import subprocess
import uuid
import time
from typing import Any, Dict, List, Optional

from mcp_vulnerabilities.probe.client import McpProbeClient
from mcp_vulnerabilities.probe.transport import StdioTransport


class SandboxError(Exception):
    """Base exception for sandbox execution errors."""
    pass


class TimeoutExpired(SandboxError):
    """Exception raised when sandbox execution exceeds configured timeout."""
    pass


def sanitize_environment(env_updates: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Sanitize the environment by stripping dangerous sensitive credentials and tokens.
    """
    dangerous_prefixes = (
        "AWS_",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "SSH_",
        "AZURE_",
        "GCP_",
        "GOOGLE_",
    )
    safe_env: Dict[str, str] = {}

    for k, v in os.environ.items():
        if any(k.startswith(prefix) for prefix in dangerous_prefixes):
            continue
        safe_env[k] = v

    if "PATH" not in safe_env:
        safe_env["PATH"] = "/usr/local/bin:/usr/bin:/bin"

    if env_updates:
        for k, v in env_updates.items():
            if any(k.startswith(prefix) for prefix in dangerous_prefixes):
                continue
            safe_env[k] = v

    return safe_env


def probe_mcp_server_stdio(
    command: List[str],
    env: Optional[Dict[str, str]] = None,
    timeout_seconds: float = 5.0,
) -> List[Dict[str, Any]]:
    """
    Spawns an MCP server over stdio and executes the discovery handshake to list tools.
    """
    if not command:
        return []

    safe_env = sanitize_environment(env)
    try:
        cmd_head = command[0]
        cmd_args = command[1:] if len(command) > 1 else []
        transport = StdioTransport(command=cmd_head, args=cmd_args, env=safe_env)
        with McpProbeClient(transport) as client:
            client.connect_and_discover(timeout=timeout_seconds, surfaces={"tools"})
            return client.tools
    except Exception:
        return []


class BaseSandboxRunner(abc.ABC):
    """Abstract base class for container and VM sandbox execution drivers."""

    def wrap_command(self, command: List[str]) -> List[str]:
        """Wrap the original command in the necessary sandbox execution command."""
        return command

    def prepare(self, command: List[str], timeout: float = 5.0) -> Any:
        """Perform any necessary pre-launch setup (like incus launch) and return a cleanup callback or None."""
        return None

    def is_available(self) -> bool:
        """Check if this sandbox runner runtime is available on the host."""
        return True

    @abc.abstractmethod
    def run_handshake(
        self, command: List[str], timeout: float = 5.0, env: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """Run the MCP protocol handshake in the isolated sandbox."""
        pass


class HostSandboxRunner(BaseSandboxRunner):
    """Direct host execution runner with environment sanitization."""

    def is_available(self) -> bool:
        return True

    def run_handshake(
        self, command: List[str], timeout: float = 5.0, env: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        return probe_mcp_server_stdio(command, env=env, timeout_seconds=timeout)


HostRunner = HostSandboxRunner


class DockerSandboxRunner(BaseSandboxRunner):
    """Isolated container execution driver using Docker or Podman."""

    def is_available(self) -> bool:
        return bool(shutil.which("docker") or shutil.which("podman"))

    def wrap_command(self, command: List[str]) -> List[str]:
        if not shutil.which("docker"):
            raise EnvironmentError("docker CLI not found in PATH")
        if not command:
            raise ValueError("Command cannot be empty")
        image = command[0]
        cmd_args = command[1:]
        return [
            "docker", "run", "-i", "--rm", "--network", "none", "--memory", "512m",
            image
        ] + cmd_args

    def run_handshake(
        self, command: List[str], timeout: float = 5.0, env: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        docker_cmd = self.wrap_command(command)
        return probe_mcp_server_stdio(docker_cmd, env=env, timeout_seconds=timeout)


class IncusSandboxRunner(BaseSandboxRunner):
    """Isolated container or VM execution driver using Canonical Incus."""

    def __init__(self, is_vm: bool = False):
        self.is_vm = is_vm
        self._instance_name: Optional[str] = None

    def is_available(self) -> bool:
        return bool(shutil.which("incus"))

    def prepare(self, command: List[str], timeout: float = 5.0) -> Any:
        if not shutil.which("incus"):
            raise EnvironmentError("incus CLI not found in PATH")
        if not command:
            raise ValueError("Command cannot be empty")

        image = command[0]
        self._instance_name = f"mcp-probe-{uuid.uuid4().hex[:8]}"

        launch_cmd = [
            "incus", "launch", f"docker:{image}", self._instance_name,
            "--ephemeral", "-c", "limits.memory=512MB", "-c", "limits.cpu=1"
        ]
        if self.is_vm:
            launch_cmd.append("--vm")

        subprocess.run(launch_cmd, check=True, capture_output=True, timeout=timeout)

        def cleanup():
            if self._instance_name:
                try:
                    subprocess.run(
                        ["incus", "delete", "-f", self._instance_name],
                        check=False,
                        capture_output=True,
                    )
                except Exception:
                    pass

        return cleanup

    def wrap_command(self, command: List[str]) -> List[str]:
        if not self._instance_name:
            self._instance_name = f"mcp-probe-{uuid.uuid4().hex[:8]}"
        cmd_args = command[1:]
        return ["incus", "exec", self._instance_name, "--"] + cmd_args

    def run_handshake(
        self, command: List[str], timeout: float = 5.0, env: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        cleanup = None
        try:
            cleanup = self.prepare(command, timeout)
            exec_cmd = self.wrap_command(command)
            return probe_mcp_server_stdio(exec_cmd, env=env, timeout_seconds=timeout)
        except Exception as exc:
            if isinstance(exc, EnvironmentError) and "not found" in str(exc):
                raise
            return []
        finally:
            if cleanup:
                cleanup()


class AutoSandboxRunner(BaseSandboxRunner):
    """Automatically selects the best available sandbox driver (Incus, Docker, or Host)."""

    def __init__(self):
        if shutil.which("incus"):
            self._runner: BaseSandboxRunner = IncusSandboxRunner()
        elif shutil.which("docker"):
            self._runner = DockerSandboxRunner()
        else:
            self._runner = HostSandboxRunner()

    def _is_host_command(self, command: List[str]) -> bool:
        if not command:
            return True
        first = command[0]
        return bool(os.path.isabs(first) or os.path.exists(first) or first.startswith(("./", "../", "/")))

    def prepare(self, command: List[str], timeout: float = 5.0) -> Any:
        if self._is_host_command(command):
            return None
        return self._runner.prepare(command, timeout)

    def wrap_command(self, command: List[str]) -> List[str]:
        if self._is_host_command(command):
            return command
        return self._runner.wrap_command(command)

    def run_handshake(
        self, command: List[str], timeout: float = 5.0, env: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        if self._is_host_command(command):
            return HostSandboxRunner().run_handshake(command, timeout, env)
        try:
            return self._runner.run_handshake(command, timeout, env)
        except Exception:
            return HostSandboxRunner().run_handshake(command, timeout, env)


def get_sandbox_runner(mode: str = "auto", **kwargs: Any) -> BaseSandboxRunner:
    """Factory function returning the configured sandbox runner."""
    if mode == "docker":
        return DockerSandboxRunner()
    elif mode == "incus":
        return IncusSandboxRunner(is_vm=False)
    elif mode == "incus-vm":
        return IncusSandboxRunner(is_vm=True)
    elif mode == "host":
        return HostSandboxRunner()
    else:
        return AutoSandboxRunner()

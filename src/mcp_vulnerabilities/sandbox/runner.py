import logging
import shlex
import subprocess
import time

from mcp_vulnerabilities.probe.client import McpProbeClient
from mcp_vulnerabilities.probe.transport import StdioTransport
from mcp_vulnerabilities.sandbox.models import SandboxInspectionResult

logger = logging.getLogger(__name__)

class SandboxError(Exception):
    pass

class TimeoutExpired(SandboxError):
    pass

class EphemeralSandbox:
    def __init__(self, engine_cmd: str, timeout: int = 60, network: str = "bridge"):
        self.engine_cmd = engine_cmd
        self.timeout = timeout
        self.network = network

    def _build_run_command(self, base_image: str) -> list[str]:
        return [
            self.engine_cmd, "run", "-d", "--rm",
            "--memory", "512m",
            "--cpus", "1.0",
            "--pids-limit", "100",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--network", self.network,
            base_image,
            "sleep", str(self.timeout + 10)
        ]

    def _get_installed_binary(self, container_id: str, ecosystem: str, package: str) -> str:
        # Discover entrypoint via entry_points.txt or package.json#bin
        if ecosystem == "pypi":
            # For PyPI, find the dist-info directory and parse entry_points.txt
            # Using find to locate entry_points.txt and grep to find console_scripts
            cmd = [
                self.engine_cmd, "exec", container_id,
                "sh", "-c",
                "find /usr/local/lib/python3.12/site-packages -name 'entry_points.txt' -exec cat {} \\; | grep -A 5 '\\[console_scripts\\]' | grep -v '\\[console_scripts\\]' | head -n 1 | cut -d'=' -f1 | tr -d ' '"
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                binary = result.stdout.strip()
                if binary:
                    return binary
            except subprocess.CalledProcessError:
                pass
                
            # Fallback to package name
            return package

        elif ecosystem == "npm":
            # For npm, just executing `npx <package>` or returning the last part of package name is usually safest
            return package.split('/')[-1] if '/' in package else package
            
        return package

    def execute(self, ecosystem: str, package: str, version: str | None = None) -> SandboxInspectionResult:
        container_id = None
        start_time = time.time()
        
        try:
            # 1. Start a long-running ephemeral container
            base_image = "python:3.12-slim" if ecosystem == "pypi" else "node:20-alpine"
            cmd = self._build_run_command(base_image)
            
            logger.debug(f"Starting sandbox container: {shlex.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            container_id = result.stdout.strip()
            
            # 2. Install the package
            target = f"{package}=={version}" if version and ecosystem == "pypi" else (f"{package}@{version}" if version else package)
            if ecosystem == "pypi":
                install_cmd = ["pip", "install", "--no-cache-dir", target]
            else:
                install_cmd = ["npm", "install", "-g", "--no-audit", "--no-fund", target]
                
            exec_cmd = [self.engine_cmd, "exec", container_id] + install_cmd
            logger.debug(f"Installing package: {shlex.join(exec_cmd)}")
            try:
                subprocess.run(exec_cmd, capture_output=True, text=True, check=True, timeout=self.timeout)
            except subprocess.TimeoutExpired:
                raise TimeoutExpired(f"Package installation timed out after {self.timeout}s")
            
            # 3. Discover entrypoint
            server_cmd = self._get_installed_binary(container_id, ecosystem, package)
            
            # 4. Probe it
            # Calculate remaining time
            elapsed = time.time() - start_time
            remaining = max(1.0, self.timeout - elapsed)
            
            if ecosystem == "pypi":
                run_cmd = [self.engine_cmd, "exec", "-i", container_id, "timeout", str(int(remaining)), server_cmd]
            else:
                run_cmd = [self.engine_cmd, "exec", "-i", container_id, "timeout", str(int(remaining)), "npx", "-y", target]
                
            logger.debug(f"Probing: {shlex.join(run_cmd)}")
            
            transport = StdioTransport(command=shlex.join(run_cmd))
            client = McpProbeClient(transport)
            
            exit_code = 0
            raw_stderr = ""
            
            try:
                # Limit the probe timeout to remaining time
                probe_timeout = min(5.0, remaining)
                client.connect_and_discover(timeout=probe_timeout)
            except Exception as e:
                logger.error(f"Probe failed: {e}")
                raw_stderr = str(e)
                exit_code = 1
                
            execution_time = time.time() - start_time
            
            # Check if time exceeded
            if execution_time > self.timeout:
                raise TimeoutExpired(f"Execution timed out after {self.timeout}s")
                
            return SandboxInspectionResult(
                package_name=package,
                ecosystem=ecosystem,
                installed_version=version,
                discovered_tools=client.tools,
                discovered_prompts=client.surface.prompts,
                raw_stderr=raw_stderr,
                execution_time_seconds=execution_time,
                exit_code=exit_code
            )
            
        except subprocess.TimeoutExpired:
            raise TimeoutExpired(f"Execution timed out after {self.timeout}s")
            
        finally:
            if container_id:
                try:
                    logger.debug(f"Cleaning up container {container_id}")
                    subprocess.run([self.engine_cmd, "rm", "-f", container_id], capture_output=True, check=False)
                except Exception:
                    pass

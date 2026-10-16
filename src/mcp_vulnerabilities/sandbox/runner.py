from __future__ import annotations

import logging
import shlex
import subprocess
import time
import tempfile
import shutil
from pathlib import Path
from typing import Optional

from mcp_vulnerabilities.probe.client import McpProbeClient
from mcp_vulnerabilities.probe.transport import StdioTransport
from mcp_vulnerabilities.sandbox.models import SandboxInspectionResult

logger = logging.getLogger(__name__)

from mcp_vulnerabilities.sandbox.drivers import SandboxError, TimeoutExpired

class EphemeralSandbox:
    def __init__(self, engine_cmd: str | None, timeout: int = 60, network: str = "bridge"):
        self.engine_cmd = engine_cmd
        self.timeout = timeout
        self.network = network

    def _build_run_command(self, base_image: str, volumes: Optional[list[str]] = None) -> list[str]:
        cmd = [
            self.engine_cmd, "run", "-d", "--rm",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", "10001:10001",
            "--memory", "512m",
            "--cpus", "1.0",
            "--pids-limit", "100",
            "-e", "HOME=/tmp",
        ]
        if volumes:
            for v in volumes:
                cmd.extend(["-v", v])
        cmd.extend([
            base_image,
            "sleep", str(self.timeout + 10)
        ])
        return cmd

    def _stage1_fetch(self, package_spec: str, ecosystem: str, target_dir: Path) -> Path:
        base_image = "python:3.12-slim" if ecosystem == "pypi" else "node:20-alpine"
        
        if ecosystem == "pypi":
            cmd = [
                self.engine_cmd, "run", "--rm",
                "-v", f"{target_dir}:/stage1_out",
                base_image,
                "pip", "download", "--no-deps", "-d", "/stage1_out", package_spec
            ]
        else:
            cmd = [
                self.engine_cmd, "run", "--rm",
                "-v", f"{target_dir}:/stage1_out",
                base_image,
                "npm", "pack", package_spec, "--pack-destination", "/stage1_out"
            ]

        logger.debug(f"Stage 1 Fetch: {shlex.join(cmd)}")
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            raise TimeoutExpired(f"Stage 1 fetch timed out after {self.timeout}s")
        except subprocess.CalledProcessError as e:
            raise SandboxError(f"Stage 1 fetch failed: {e.stderr}")
            
        files = list(target_dir.glob("*"))
        if not files:
            raise SandboxError("Stage 1 fetch produced no files")
        return files[0]

    def _get_installed_binary(self, container_id: str, ecosystem: str, package: str) -> str:
        if ecosystem == "pypi":
            cmd = [
                self.engine_cmd, "exec", container_id,
                "sh", "-c",
                r"find /tmp -name 'entry_points.txt' -exec cat {} \; | grep -A 5 '\[console_scripts\]' | grep -v '\[console_scripts\]' | head -n 1 | cut -d'=' -f1 | tr -d ' '"
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                binary = result.stdout.strip()
                if binary:
                    return f"/tmp/.local/bin/{binary}" if not binary.startswith("/") else binary
            except subprocess.CalledProcessError:
                pass
            return package

        elif ecosystem == "npm":
            return package.split('/')[-1] if '/' in package else package
            
        return package

    def _stage2_inspect(self, package_file: Path, ecosystem: str, package: str, version: str | None, start_time: float) -> SandboxInspectionResult:
        base_image = "python:3.12-slim" if ecosystem == "pypi" else "node:20-alpine"
        container_id = None
        
        try:
            run_cmd = self._build_run_command(base_image, volumes=[f"{package_file.parent}:/pkg:ro"])
            
            logger.debug(f"Starting isolated sandbox container: {shlex.join(run_cmd)}")
            result = subprocess.run(run_cmd, capture_output=True, text=True, check=True)
            container_id = result.stdout.strip()
            
            target_file = f"/pkg/{package_file.name}"
            
            if ecosystem == "pypi":
                install_cmd = [
                    "pip", "install", "--no-cache-dir", "--no-deps", "--no-index",
                    "--find-links", "/pkg", "--user", target_file
                ]
            else:
                install_cmd = [
                    "npm", "install", "--prefix", "/tmp", "--offline",
                    "--no-audit", "--no-fund", target_file
                ]
                
            exec_cmd = [self.engine_cmd, "exec", "-w", "/tmp", container_id] + install_cmd
            logger.debug(f"Installing package offline: {shlex.join(exec_cmd)}")
            try:
                subprocess.run(exec_cmd, capture_output=True, text=True, check=True, timeout=self.timeout)
            except subprocess.TimeoutExpired:
                raise TimeoutExpired(f"Package installation timed out after {self.timeout}s")
            except subprocess.CalledProcessError as e:
                raise SandboxError(f"Package installation failed: {e.stderr}")
            
            server_cmd = self._get_installed_binary(container_id, ecosystem, package)
            
            elapsed = time.time() - start_time
            remaining = max(1.0, self.timeout - elapsed)
            
            if ecosystem == "pypi":
                probe_cmd = [self.engine_cmd, "exec", "-i", "-w", "/tmp", container_id, "timeout", str(int(remaining)), "python", "-m", package.replace('-', '_')]
                if server_cmd != package and "/" in server_cmd:
                    probe_cmd = [self.engine_cmd, "exec", "-i", "-w", "/tmp", container_id, "timeout", str(int(remaining)), "python", server_cmd]
            else:
                probe_cmd = [self.engine_cmd, "exec", "-i", "-w", "/tmp", container_id, "timeout", str(int(remaining)), "npx", "--no-install", server_cmd]
                
            logger.debug(f"Probing: {shlex.join(probe_cmd)}")
            
            transport = StdioTransport(command=shlex.join(probe_cmd))
            client = McpProbeClient(transport)
            
            exit_code = 0
            raw_stderr = ""
            
            try:
                probe_timeout = min(5.0, remaining)
                client.connect_and_discover(timeout=probe_timeout)
            except Exception as e:
                logger.error(f"Probe failed: {e}")
                raw_stderr = str(e)
                exit_code = 1
                
            execution_time = time.time() - start_time
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
                exit_code=exit_code,
                status="completed"
            )
            
        except subprocess.TimeoutExpired:
            raise TimeoutExpired(f"Execution timed out after {self.timeout}s")
            
        finally:
            if container_id:
                try:
                    subprocess.run([self.engine_cmd, "rm", "-f", container_id], capture_output=True, check=False)
                except Exception:
                    pass

    def execute(self, ecosystem: str, package: str, version: str | None = None) -> SandboxInspectionResult:
        start_time = time.time()
        
        if not self.engine_cmd:
            return SandboxInspectionResult(
                package_name=package,
                ecosystem=ecosystem,
                installed_version=version,
                discovered_tools=[],
                discovered_prompts=[],
                raw_stderr="",
                execution_time_seconds=0.0,
                exit_code=0,
                status="skipped",
                reason="Container engine not detected"
            )

        package_spec = f"{package}=={version}" if version and ecosystem == "pypi" else (f"{package}@{version}" if version else package)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            target_dir = Path(tmpdir)
            target_dir.chmod(0o777)
            
            package_file = self._stage1_fetch(package_spec, ecosystem, target_dir)
            return self._stage2_inspect(package_file, ecosystem, package, version, start_time)

import subprocess


class ContainerEngine:
    def __init__(self):
        self.runtime = self._detect_runtime()
        
    def _detect_runtime(self) -> str | None:
        """Detect available container runtime (docker or podman)."""
        for runtime in ["docker", "podman"]:
            try:
                subprocess.run(
                    [runtime, "info"], 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL, 
                    check=True,
                    timeout=5
                )
                return runtime
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return None

    def is_available(self) -> bool:
        return self.runtime is not None
        
    def get_runtime(self) -> str | None:
        return self.runtime
        
    def get_version(self) -> str | None:
        if not self.runtime:
            return None
        try:
            result = subprocess.run(
                [self.runtime, "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return None

from dataclasses import dataclass
from typing import Any

@dataclass
class SandboxInspectionResult:
    package_name: str
    ecosystem: str
    installed_version: str | None
    discovered_tools: list[dict[str, Any]]
    discovered_prompts: list[dict[str, Any]]
    raw_stderr: str
    execution_time_seconds: float
    exit_code: int | None
    status: str = "completed"
    reason: str | None = None

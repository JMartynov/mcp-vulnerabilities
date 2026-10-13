from dataclasses import dataclass
from enum import Enum
from typing import Optional


class TaintSinkCategory(str, Enum):
    COMMAND_INJECTION = "COMMAND_INJECTION"
    CODE_EVALUATION = "CODE_EVALUATION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SQL_INJECTION = "SQL_INJECTION"
    SSRF_EGRESS = "SSRF_EGRESS"


@dataclass
class TaintFinding:
    tool_name: str
    parameter_name: str
    source_line: int
    sink_call: str
    sink_category: TaintSinkCategory
    sink_line: int
    severity: str  # CRITICAL, HIGH, MEDIUM
    code_snippet: str
    remediation: str
    file_path: Optional[str] = None

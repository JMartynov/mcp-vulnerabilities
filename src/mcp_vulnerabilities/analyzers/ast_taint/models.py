from dataclasses import dataclass
from enum import Enum
from typing import Optional, Set


class TaintSinkCategory(str, Enum):
    COMMAND_INJECTION = "COMMAND_INJECTION"
    CODE_EVALUATION = "CODE_EVALUATION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SQL_INJECTION = "SQL_INJECTION"
    SSRF_EGRESS = "SSRF_EGRESS"

KNOWN_SANITIZERS = {
    # Shell injection sanitizers
    "shlex.quote": {TaintSinkCategory.COMMAND_INJECTION},
    # Path traversal sanitizers
    "os.path.basename": {TaintSinkCategory.PATH_TRAVERSAL},
    "basename": {TaintSinkCategory.PATH_TRAVERSAL},
    "pathlib.Path.resolve": {TaintSinkCategory.PATH_TRAVERSAL},
    # Numeric casts sanitize command, eval, sql, ssrf, traversal
    "int": {TaintSinkCategory.COMMAND_INJECTION, TaintSinkCategory.SQL_INJECTION, TaintSinkCategory.PATH_TRAVERSAL, TaintSinkCategory.CODE_EVALUATION},
    "float": {TaintSinkCategory.COMMAND_INJECTION, TaintSinkCategory.SQL_INJECTION, TaintSinkCategory.PATH_TRAVERSAL, TaintSinkCategory.CODE_EVALUATION},
    # RegEx / URL sanitizers
    "re.escape": {TaintSinkCategory.COMMAND_INJECTION},
    "urllib.parse.quote": {TaintSinkCategory.SSRF_EGRESS},
    "quote": {TaintSinkCategory.COMMAND_INJECTION, TaintSinkCategory.SSRF_EGRESS},
}


@dataclass
class TaintState:
    parameter_name: str
    sanitized_categories: Set[TaintSinkCategory]


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

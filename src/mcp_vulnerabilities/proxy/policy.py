import dataclasses
import json
import re
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.database.matcher import VulnerabilityMatcher

@dataclasses.dataclass
class PolicyDecision:
    allowed: bool
    rule_id: str
    reason: str
    severity: str = "HIGH"

@dataclasses.dataclass
class AuditEvent:
    event_type: str
    severity: str
    details: str
    context: dict[str, Any]
    action_taken: str

class ProxyPolicyEngine:
    def __init__(
        self,
        package_name: str | None = None,
        blocked_tools: set[str] | None = None,
        allowed_tools: set[str] | None = None,
        strict_passport: bool = False,
        enable_payload_guardrails: bool = True,
        vulnerabilities_dir: Path | None = None,
    ):
        self.package_name = package_name
        self.blocked_tools = blocked_tools or set()
        self.allowed_tools = allowed_tools or set()
        self.strict_passport = strict_passport
        self.enable_payload_guardrails = enable_payload_guardrails
        self.vulnerabilities_dir = vulnerabilities_dir

        if self.package_name and self.vulnerabilities_dir:
            self._load_vulnerabilities()

    def _load_vulnerabilities(self):
        matcher = VulnerabilityMatcher(self.vulnerabilities_dir)
        vulnerable_tools = matcher.get_vulnerable_tools(self.package_name)
        self.blocked_tools.update(vulnerable_tools)

    def evaluate_request(self, msg: dict[str, Any]) -> PolicyDecision:
        if msg.get("method") != "tools/call":
            return PolicyDecision(True, "DEFAULT_ALLOW", "Not a tools/call")
        
        tool_name = msg.get("params", {}).get("name")
        if not tool_name:
            return PolicyDecision(True, "DEFAULT_ALLOW", "No tool name")

        if tool_name in self.blocked_tools:
            return PolicyDecision(False, "BLOCKED_TOOL", f"Tool {tool_name} is blocked")

        if self.strict_passport and self.allowed_tools and tool_name not in self.allowed_tools:
            return PolicyDecision(False, "UNADVERTISED_TOOL", f"Tool {tool_name} not in allowed list")

        if self.enable_payload_guardrails:
            args = msg.get("params", {}).get("arguments", {})
            for arg_val in args.values():
                if isinstance(arg_val, str):
                    if "../" in arg_val or "..\\" in arg_val:
                        return PolicyDecision(False, "PAYLOAD_GUARDRAIL_VIOLATION", "Path traversal detected")
                    if re.search(r";\s*DROP\s+TABLE", arg_val, re.IGNORECASE) or re.search(r";.*--", arg_val):
                        return PolicyDecision(False, "PAYLOAD_GUARDRAIL_VIOLATION", "SQL injection detected")
                    if "$(" in arg_val or "`" in arg_val or "|" in arg_val or ";" in arg_val:
                        return PolicyDecision(False, "PAYLOAD_GUARDRAIL_VIOLATION", "Shell injection detected")
                    
        return PolicyDecision(True, "ALLOW", "Request allowed")

    def inspect_response(self, msg: dict[str, Any], request_method: str | None = None) -> tuple[dict[str, Any], list[AuditEvent]]:
        events = []
        if request_method == "tools/list":
            result = msg.get("result", {})
            if "tools" in result:
                tools = result["tools"]
                filtered_tools = []
                for tool in tools:
                    tool_name = tool.get("name")
                    if self.strict_passport and self.allowed_tools and tool_name not in self.allowed_tools:
                        events.append(AuditEvent("SHADOW_TOOL_DETECTED", "CRITICAL", f"Unadvertised tool {tool_name}", {"tool": tool_name}, "Stripped from tools/list"))
                        continue
                    filtered_tools.append(tool)
                
                # Create a copy so we do not mutate in place for all callers if not desired
                new_msg = dict(msg)
                new_msg["result"] = dict(result)
                new_msg["result"]["tools"] = filtered_tools
                return new_msg, events
        return msg, events

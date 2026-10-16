"""Capability Risk Classifier & Human-Readable Security Commentary Engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

CMD_PATTERN = re.compile(
    r"\b(cmd|command|exec|script|shell|bash|powershell|eval)\b", re.IGNORECASE
)
SQL_PATTERN = re.compile(
    r"\b(query|sql|statement|raw_sql|clause|filter_query)\b", re.IGNORECASE
)
FS_PATTERN = re.compile(
    r"\b(path|filepath|filename|dest|destination|directory)\b", re.IGNORECASE
)
SSRF_PATTERN = re.compile(r"\b(url|endpoint|webhook|target_host|uri)\b", re.IGNORECASE)
CRED_PATTERN = re.compile(r"\b(api_key|secret|token|password)\b", re.IGNORECASE)
CONTENT_PATTERN = re.compile(r"\bcontent\b", re.IGNORECASE)
WRITE_SAVE_PATTERN = re.compile(r"\b(write|save)\b", re.IGNORECASE)
ENV_PATTERN = re.compile(r"\b(env|environment|setenv|getenv)\b", re.IGNORECASE)
PROMPT_PATTERN = re.compile(r"\b(prompt|instruction|override|ignore)\b", re.IGNORECASE)


class RiskCategory(str, Enum):
    COMMAND_EXECUTION = "Arbitrary Command Execution"
    FILE_SYSTEM = "File System Access"
    NETWORK = "Network Egress"
    CREDENTIALS = "Credential & Secret Access"
    PROMPT_INJECTION = "Prompt Injection"
    ENV_TAMPERING = "Environment Variable Tampering"
    SAFE = "Safe Operations"


class SeverityTier(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


@dataclass
class ToolRiskClassification:
    tool_name: str
    severity: SeverityTier
    categories: set[RiskCategory] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)


def analyze_tool_security(tool: dict[str, Any]) -> dict[str, Any]:
    tool_name = tool.get("name", "")
    tool_desc = tool.get("description", "")
    input_schema = tool.get("inputSchema", {}) or tool.get("input_schema", {})
    properties = (
        input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
    )

    risks = set()

    def evaluate(text: str):
        if not text:
            return

        if CMD_PATTERN.search(text):
            risks.add("command_execution")

        if SQL_PATTERN.search(text):
            risks.add("sql_injection")

        if FS_PATTERN.search(text):
            risks.add("filesystem_mutation")

        if SSRF_PATTERN.search(text):
            risks.add("ssrf")

        if CRED_PATTERN.search(text):
            risks.add("credential_exposure")

        if ENV_PATTERN.search(text):
            risks.add("env_tampering")

        if PROMPT_PATTERN.search(text):
            risks.add("prompt_injection")

    def evaluate_content(name: str, desc: str):
        if CONTENT_PATTERN.search(name) or CONTENT_PATTERN.search(desc):
            if WRITE_SAVE_PATTERN.search(name) or WRITE_SAVE_PATTERN.search(desc):
                risks.add("filesystem_mutation")

    # Evaluate tool level
    evaluate(tool_name)
    evaluate(tool_desc)
    evaluate_content(tool_name, tool_desc)

    # Evaluate properties
    if isinstance(properties, dict):
        for prop_name, prop_val in properties.items():
            evaluate(prop_name)
            prop_desc = (
                prop_val.get("description", "") if isinstance(prop_val, dict) else ""
            )
            evaluate(prop_desc)
            evaluate_content(prop_name, prop_desc)

    # Calculate score
    score = 0.0
    if "command_execution" in risks:
        score += 5.0
    if "sql_injection" in risks:
        score += 4.0
    if "filesystem_mutation" in risks:
        score += 3.0
    if "ssrf" in risks:
        score += 2.5
    if "credential_exposure" in risks:
        score += 2.0
    if "env_tampering" in risks:
        score += 2.0
    if "prompt_injection" in risks:
        score += 1.5

    score = min(score, 10.0)

    if score >= 7.0:
        tier = "critical"
    elif score >= 5.0:
        tier = "high"
    elif score >= 2.5:
        tier = "medium"
    else:
        tier = "low"

    safe = tier not in ("critical", "high")

    return {
        "risk_indicators": sorted(list(risks)),
        "risk_score": score,
        "risk_tier": tier,
        "safe_for_autonomous_agents": safe,
    }


def classify_server_security_profile(versions: list[dict[str, Any]]) -> dict[str, Any]:
    if not versions:
        return {
            "highest_risk_tier": "low",
            "total_tools_analyzed": 0,
            "critical_tools_count": 0,
            "high_risk_tools_count": 0,
        }

    latest_version = versions[0]
    try:
        from packaging.version import parse
        latest_version = max(versions, key=lambda v: parse(v.get("version", "0.0.0")))
    except Exception:
        pass

    tools = latest_version.get("tool_signatures", []) or latest_version.get("tools", [])
    processed_tools = []
    for t in tools:
        if hasattr(t, "to_dict"):
            processed_tools.append(t.to_dict())
        elif isinstance(t, dict):
            processed_tools.append(t)

    total = len(processed_tools)
    critical = 0
    high = 0
    highest_score = -1.0
    highest_tier = "low"

    for tool in processed_tools:
        res = analyze_tool_security(tool)
        tier = res["risk_tier"]
        score = res["risk_score"]
        if tier == "critical":
            critical += 1
        elif tier == "high":
            high += 1

        if score > highest_score:
            highest_score = score
            highest_tier = tier

    if total == 0:
        highest_tier = "low"

    return {
        "highest_risk_tier": highest_tier,
        "total_tools_analyzed": total,
        "critical_tools_count": critical,
        "high_risk_tools_count": high,
    }


def generate_tool_security_comment(
    tool: dict[str, Any],
    analysis: dict[str, Any] | None = None,
    affecting_advisories: list[Any] | None = None,
) -> str:
    if analysis is None:
        analysis = analyze_tool_security(tool)

    tool_name = tool.get("name", "tool")
    tier = analysis.get("risk_tier", "low").upper()
    indicators = analysis.get("risk_indicators", [])

    comments = []
    if "command_execution" in indicators:
        comments.append("executes arbitrary host system commands or shell scripts")
    if "sql_injection" in indicators:
        comments.append("issues raw database queries that could lead to SQL injection")
    if "filesystem_mutation" in indicators:
        comments.append("reads, writes, or modifies host filesystem paths")
    if "ssrf" in indicators:
        comments.append("initiates outbound network requests (potential SSRF risk)")
    if "credential_exposure" in indicators:
        comments.append("handles sensitive credentials, tokens, or private secrets")
    if "env_tampering" in indicators:
        comments.append("inspects or modifies host environment variables")
    if "prompt_injection" in indicators:
        comments.append("processes unstructured prompts susceptible to injection overrides")

    if not comments:
        detail = f"Tool `{tool_name}` operates with safe parameters and poses minimal static capability risk."
    else:
        detail = f"Tool `{tool_name}` [{tier}] " + "; ".join(comments) + "."

    if affecting_advisories:
        detail += f" Warning: Affected by {len(affecting_advisories)} known security advisories."

    return detail


def generate_server_security_summary(
    package_name: str,
    profile: dict[str, Any],
    vuln_versions_count: int = 0,
    safe_versions_count: int = 0,
) -> str:
    tier = profile.get("highest_risk_tier", "low").upper()
    total = profile.get("total_tools_analyzed", 0)
    critical = profile.get("critical_tools_count", 0)
    high = profile.get("high_risk_tools_count", 0)

    summary = (
        f"Server `{package_name}` evaluated with highest capability tier [{tier}]. "
        f"Analyzed {total} tools ({critical} critical, {high} high risk). "
        f"Vulnerability audit: {vuln_versions_count} vulnerable version(s), {safe_versions_count} safe version(s)."
    )
    return summary


class CapabilityRiskClassifier:
    """Classifies tools into structured risk categories and severity tiers."""

    def __init__(self):
        self._command_heuristics = [
            "exec", "eval", "shell", "run", "cmd", "bash", "sh", "system"
        ]
        self._fs_heuristics = [
            "read", "write", "file", "path", "dir", "mkdir", "rm", "delete", "copy", "move", "fs"
        ]
        self._network_heuristics = [
            "fetch", "request", "http", "url", "curl", "wget", "api", "download", "network"
        ]
        self._credential_heuristics = [
            "secret", "token", "password", "cred", "key", "auth"
        ]
        self._env_heuristics = [
            "env", "setenv", "getenv"
        ]
        self._prompt_injection_heuristics = [
            "prompt", "instruction", "override", "ignore"
        ]

    def classify_tool(self, tool: dict[str, Any]) -> ToolRiskClassification:
        name = str(tool.get("name", "")).lower()
        desc = str(tool.get("description", "")).lower()
        input_schema = tool.get("inputSchema", {}) or tool.get("input_schema", {})
        properties = (
            input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
        )
        param_names = [str(k).lower() for k in properties.keys()]

        categories: set[RiskCategory] = set()
        reasons: list[str] = []
        severity = SeverityTier.SAFE

        # Command Execution
        is_cmd = (any(h in name for h in self._command_heuristics) and name != "run_prompt") or any(
            h in param_names for h in ["command", "cmd", "script", "code"]
        ) or CMD_PATTERN.search(name) or CMD_PATTERN.search(desc)
        if is_cmd:
            categories.add(RiskCategory.COMMAND_EXECUTION)
            reasons.append("Tool signature suggests arbitrary command or code execution capabilities.")
            severity = SeverityTier.CRITICAL

        # Credentials
        is_cred = any(h in name for h in self._credential_heuristics) or any(
            h in param_names for h in ["secret", "token", "password", "api_key", "key"]
        ) or CRED_PATTERN.search(name)
        if is_cred:
            categories.add(RiskCategory.CREDENTIALS)
            reasons.append("Tool signature suggests access to credentials or secrets.")
            if severity != SeverityTier.CRITICAL:
                severity = SeverityTier.HIGH

        # Environment
        is_env = any(h in name for h in self._env_heuristics) or any(
            h in param_names for h in ["env", "setenv", "getenv"]
        )
        if is_env:
            categories.add(RiskCategory.ENV_TAMPERING)
            reasons.append("Tool signature suggests environment variable access or modification.")
            if severity not in (SeverityTier.CRITICAL, SeverityTier.HIGH):
                severity = SeverityTier.HIGH

        # File System
        is_fs = any(h in name for h in self._fs_heuristics) or any(
            h in param_names for h in ["path", "filename", "filepath", "content"]
        ) or FS_PATTERN.search(name) or FS_PATTERN.search(desc)
        if is_fs:
            categories.add(RiskCategory.FILE_SYSTEM)
            reasons.append("Tool signature suggests file system access (read/write/modify).")
            if severity not in (SeverityTier.CRITICAL, SeverityTier.HIGH):
                if any(w in name for w in ["write", "delete", "rm", "save", "mkdir"]):
                    severity = SeverityTier.HIGH
                else:
                    severity = SeverityTier.MEDIUM

        # Network
        is_net = any(h in name for h in self._network_heuristics) or any(
            h in param_names for h in ["url", "endpoint", "uri"]
        ) or SSRF_PATTERN.search(name)
        if is_net:
            categories.add(RiskCategory.NETWORK)
            reasons.append("Tool signature suggests outbound network egress.")
            if severity not in (SeverityTier.CRITICAL, SeverityTier.HIGH):
                severity = SeverityTier.MEDIUM

        # Prompt Injection
        is_prompt = any(h in name for h in self._prompt_injection_heuristics) or any(
            h in param_names for h in ["prompt", "instruction"]
        ) or PROMPT_PATTERN.search(name)
        if is_prompt:
            categories.add(RiskCategory.PROMPT_INJECTION)
            reasons.append("Tool signature suggests unstructured prompt or instruction processing.")
            if severity not in (SeverityTier.CRITICAL, SeverityTier.HIGH):
                severity = SeverityTier.MEDIUM

        if not categories:
            categories.add(RiskCategory.SAFE)
            severity = SeverityTier.SAFE

        return ToolRiskClassification(
            tool_name=tool.get("name", ""),
            severity=severity,
            categories=categories,
            reasons=reasons,
        )


@dataclass
class ServerCommentaryResult:
    server_name: str
    overall_severity: SeverityTier
    summary: str
    tool_commentaries: list[dict[str, Any]]
    mitigation_advice: list[str]


class SecurityCommentaryEngine:
    """Generates human-readable security commentary and mitigations."""

    def generate_tool_commentary(self, classification: ToolRiskClassification) -> dict[str, Any]:
        mitigations = []
        risks = []

        if RiskCategory.COMMAND_EXECUTION in classification.categories:
            risks.append("Executes arbitrary code or commands on the host environment.")
            mitigations.append("Run server in a hardened container sandbox with dropped capabilities and read-only root.")
        if RiskCategory.FILE_SYSTEM in classification.categories:
            if classification.severity == SeverityTier.HIGH:
                risks.append("May modify or delete files on the local filesystem.")
                mitigations.append("Restrict write paths to an isolated ephemeral temp directory.")
            else:
                risks.append("Reads files from the host filesystem.")
                mitigations.append("Limit read access to required directories and enable strict path canonicalization.")
        if RiskCategory.CREDENTIALS in classification.categories:
            risks.append("May access or manage sensitive credentials or API keys.")
            mitigations.append("Pass credentials via dedicated environment variables rather than prompt inputs.")
        if RiskCategory.ENV_TAMPERING in classification.categories:
            risks.append("May access or modify environment variables.")
            mitigations.append("Sanitize environment and block tampering with sensitive configuration keys.")
        if RiskCategory.NETWORK in classification.categories:
            risks.append("Initiates outbound network requests.")
            mitigations.append("Apply egress firewall filtering or network namespace isolation.")
        if RiskCategory.PROMPT_INJECTION in classification.categories:
            risks.append("Interprets unstructured text which may lead to indirect prompt injection.")
            mitigations.append("Validate schema inputs and isolate system prompt instructions.")
        if RiskCategory.SAFE in classification.categories:
            risks.append("Standard safe operations.")
            mitigations.append("Standard operational monitoring.")

        summary = f"Tool `{classification.tool_name}`: " + " ".join(risks)
        return {
            "tool_name": classification.tool_name,
            "severity": classification.severity.value,
            "summary": summary,
            "risks": risks,
            "mitigations": mitigations,
        }

    def generate_server_commentary(
        self, server_name: str, tool_classifications: list[ToolRiskClassification]
    ) -> ServerCommentaryResult:
        if not tool_classifications:
            return ServerCommentaryResult(
                server_name=server_name,
                overall_severity=SeverityTier.SAFE,
                summary="No tools found or analyzed.",
                tool_commentaries=[],
                mitigation_advice=[],
            )

        severities = [t.severity for t in tool_classifications]
        if SeverityTier.CRITICAL in severities:
            overall = SeverityTier.CRITICAL
        elif SeverityTier.HIGH in severities:
            overall = SeverityTier.HIGH
        elif SeverityTier.MEDIUM in severities:
            overall = SeverityTier.MEDIUM
        elif SeverityTier.LOW in severities:
            overall = SeverityTier.LOW
        else:
            overall = SeverityTier.SAFE

        tool_commentaries = [self.generate_tool_commentary(t) for t in tool_classifications]
        all_mitigations = []
        for tc in tool_commentaries:
            for m in tc["mitigations"]:
                if m not in all_mitigations:
                    all_mitigations.append(m)

        if overall == SeverityTier.SAFE:
            summary = f"Server `{server_name}` is generally safe with low-impact tools."
        elif overall == SeverityTier.MEDIUM:
            summary = f"Server `{server_name}` exposes moderate risk operations (e.g. read-only filesystem or network egress)."
        else:
            summary = f"Server `{server_name}` exposes high-risk tools requiring isolation and strict permissions."

        return ServerCommentaryResult(
            server_name=server_name,
            overall_severity=overall,
            summary=summary,
            tool_commentaries=tool_commentaries,
            mitigation_advice=all_mitigations,
        )

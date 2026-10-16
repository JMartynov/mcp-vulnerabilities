"""Multi-Server Tool Conflict, Shadowing, and Collision Detection Engine."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.analyzers.capability_classifier import analyze_tool_security

logger = logging.getLogger("mcp_vulnerabilities.audit.conflict_detector")


@dataclass
class ToolInstance:
    """An instance of a tool exposed by a specific configured MCP server."""

    tool_name: str
    server_key: str
    package_name: str
    description: str
    canonical_hash: str
    property_keys: list[str]
    required_keys: list[str]
    parameter_types: dict[str, str]
    risk_tier: str
    risk_score: float
    risk_indicators: list[str]


@dataclass
class ToolCollision:
    """A detected collision where multiple servers expose the same tool name."""

    tool_name: str
    servers: list[str]
    packages: list[str]
    schema_identical: bool
    risk_tier: str
    risk_indicators: list[str]
    divergence_details: str | None = None


@dataclass
class ConflictAuditReport:
    """Consolidated audit report evaluating an MCP client configuration."""

    servers_configured: list[str]
    servers_matched_in_passports: list[str]
    total_tools_exposed: int
    unique_tool_names: int
    collisions: list[ToolCollision] = field(default_factory=list)
    has_critical_conflicts: bool = False
    is_clean: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "servers_configured": self.servers_configured,
            "servers_matched_in_passports": self.servers_matched_in_passports,
            "total_tools_exposed": self.total_tools_exposed,
            "unique_tool_names": self.unique_tool_names,
            "has_critical_conflicts": self.has_critical_conflicts,
            "is_clean": self.is_clean,
            "collisions": [
                {
                    "tool_name": c.tool_name,
                    "servers": c.servers,
                    "packages": c.packages,
                    "schema_identical": c.schema_identical,
                    "risk_tier": c.risk_tier,
                    "risk_indicators": c.risk_indicators,
                    "divergence_details": c.divergence_details,
                }
                for c in self.collisions
            ],
        }


def extract_package_from_server_config(
    server_conf: dict[str, Any], server_key: str
) -> str:
    """
    Attempt to infer package name or identifier from server command, args, or key.
    """
    args = server_conf.get("args", [])
    cmd = server_conf.get("command", "")

    # Handle Zed format where command is a dict
    if isinstance(cmd, dict):
        args = cmd.get("args", [])
        cmd = cmd.get("path", "")

    # Check args for package names (e.g. npx -y @scope/pkg or uvx pkg)
    for arg in args:
        if isinstance(arg, str):
            if arg.startswith("@") and "/" in arg:
                return arg
            if not arg.startswith("-") and not arg.endswith(
                (".js", ".ts", ".py", ".json")
            ):
                return arg

    return server_key



def load_passport_index(passports_dir: Path | str) -> dict[str, dict[str, Any]]:
    """Build a lookup index from package_name and safe names to passport dicts."""
    p_path = Path(passports_dir)
    index: dict[str, dict[str, Any]] = {}

    if p_path.is_file() and str(p_path).endswith(".gz"):
        import gzip

        try:
            with gzip.open(p_path, "rt", encoding="utf-8") as gz_f:
                data = json.load(gz_f)
                if isinstance(data, list):
                    for entry in data:
                        pkg = entry.get("package_name")
                        if pkg:
                            index[pkg.lower()] = entry
                            safe_name = (
                                pkg.replace("@", "")
                                .replace("/", "-")
                                .replace("_", "-")
                                .lower()
                            )
                            index[safe_name] = entry
                            base_name = pkg.split("/")[-1].lower()
                            if base_name not in index:
                                index[base_name] = entry
                elif isinstance(data, dict):
                    index.update(data)
        except Exception as e:
            logger.warning("Failed to load compressed passports from %s: %s", p_path, e)
        return index

    if p_path.is_dir():
        for f in p_path.rglob("*.json"):
            if f.name in ("sync_state.json", "index.json", ".passport_index.pickle"):
                continue
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                pkg = data.get("package_name")
                if pkg:
                    index[pkg.lower()] = data
                    safe_name = (
                        pkg.replace("@", "")
                        .replace("/", "-")
                        .replace("_", "-")
                        .lower()
                    )
                    index[safe_name] = data
                    base_name = pkg.split("/")[-1].lower()
                    if base_name not in index:
                        index[base_name] = data
            except Exception:
                continue
        if index:
            return index

    fallback_gz = Path("data/passports.json.gz")
    if fallback_gz.is_file():
        return load_passport_index(fallback_gz)

    return index


def audit_client_config(
    config_data: dict[str, Any] | str | Path,
    passports_dir: Path | str = "data/fingerprints",
) -> ConflictAuditReport:
    """
    Audit an MCP client configuration (Claude Desktop, Cursor, Cline, Zed) for tool collisions.
    """
    if isinstance(config_data, (str, Path)):
        p = Path(config_data)
        if not p.is_file():
            raise FileNotFoundError(f"Client configuration file not found: {p}")
        raw_conf = json.loads(p.read_text(encoding="utf-8"))
    else:
        raw_conf = config_data

    servers_dict: dict[str, Any] = {}
    if "mcpServers" in raw_conf and isinstance(raw_conf["mcpServers"], dict):
        servers_dict = raw_conf["mcpServers"]
    elif "context_servers" in raw_conf and isinstance(raw_conf["context_servers"], dict):
        servers_dict = raw_conf["context_servers"]
    elif any(isinstance(v, dict) and ("command" in v or "url" in v) for v in raw_conf.values()):
        servers_dict = raw_conf

    passport_index = load_passport_index(passports_dir)

    configured_server_names = list(servers_dict.keys())
    matched_servers: list[str] = []
    tool_instances_by_name: dict[str, list[ToolInstance]] = {}

    total_tools = 0

    for s_key, s_conf in servers_dict.items():
        if not isinstance(s_conf, dict):
            continue

        inferred_pkg = extract_package_from_server_config(s_conf, s_key).lower()
        passport = passport_index.get(inferred_pkg) or passport_index.get(s_key.lower())

        if passport:
            matched_servers.append(s_key)
            versions = passport.get("versions", [])
            latest_version = versions[0] if versions else {}
            tools = latest_version.get("tool_signatures", [])
        else:
            tools = s_conf.get("tools", [])

        for t in tools:
            total_tools += 1
            t_name = t.get("name", "")
            if not t_name:
                continue

            sec = analyze_tool_security(t)
            inst = ToolInstance(
                tool_name=t_name,
                server_key=s_key,
                package_name=passport.get("package_name", s_key) if passport else s_key,
                description=t.get("description", ""),
                canonical_hash=t.get("canonical_hash", ""),
                property_keys=list(t.get("property_keys", [])),
                required_keys=list(t.get("required_keys", [])),
                parameter_types=dict(t.get("parameter_types", {})),
                risk_tier=sec.get("risk_tier", "low"),
                risk_score=sec.get("risk_score", 0.0),
                risk_indicators=sec.get("risk_indicators", []),
            )
            tool_instances_by_name.setdefault(t_name, []).append(inst)

    collisions: list[ToolCollision] = []
    has_critical = False

    for t_name, instances in tool_instances_by_name.items():
        servers_exposing = sorted(list({inst.server_key for inst in instances}))
        if len(servers_exposing) > 1:
            packages_exposing = sorted(list({inst.package_name for inst in instances}))
            first_hash = instances[0].canonical_hash
            is_identical = bool(first_hash) and all(
                inst.canonical_hash == first_hash for inst in instances
            )

            highest_risk_score = -1.0
            highest_risk_tier = "low"
            all_indicators = set()

            for inst in instances:
                all_indicators.update(inst.risk_indicators)
                if inst.risk_score > highest_risk_score:
                    highest_risk_score = inst.risk_score
                    highest_risk_tier = inst.risk_tier

            if highest_risk_tier in ("critical", "high"):
                has_critical = True

            divergence_details = None
            if not is_identical:
                divergence_details = (
                    f"Conflicting schema implementations across {len(instances)} servers. "
                    f"Parameter signatures or descriptions differ between {', '.join(servers_exposing)}."
                )

            collision = ToolCollision(
                tool_name=t_name,
                servers=servers_exposing,
                packages=packages_exposing,
                schema_identical=is_identical,
                risk_tier=highest_risk_tier,
                risk_indicators=sorted(list(all_indicators)),
                divergence_details=divergence_details,
            )
            collisions.append(collision)

    is_clean = len(collisions) == 0

    return ConflictAuditReport(
        servers_configured=configured_server_names,
        servers_matched_in_passports=sorted(list(set(matched_servers))),
        total_tools_exposed=total_tools,
        unique_tool_names=len(tool_instances_by_name),
        collisions=collisions,
        has_critical_conflicts=has_critical,
        is_clean=is_clean,
    )


def format_audit_report(report: ConflictAuditReport) -> str:
    """Render a human-readable CLI report with security recommendations."""
    lines = [
        "==================================================",
        "      MCP MULTI-SERVER CONFLICT AUDIT REPORT      ",
        "==================================================",
        f"Configured Servers: {len(report.servers_configured)} ({', '.join(report.servers_configured)})",
        f"Matched Passports:  {len(report.servers_matched_in_passports)}",
        f"Total Tools:        {report.total_tools_exposed}",
        f"Unique Tool Names:  {report.unique_tool_names}",
        f"Collision Count:    {len(report.collisions)}",
    ]

    if report.is_clean:
        lines.append("Status:             ✅ CLEAN (No tool collisions detected)")
        lines.append("==================================================")
        return "\n".join(lines)

    lines.append(
        "Status:             ⚠️  COLLISIONS DETECTED"
        if not report.has_critical_conflicts
        else "Status:             🚨 CRITICAL CONFLICTS DETECTED"
    )
    lines.append("--------------------------------------------------")
    lines.append("DETECTED TOOL COLLISIONS:")

    for idx, c in enumerate(report.collisions, 1):
        tier_symbol = "🚨" if c.risk_tier in ("critical", "high") else "⚠️"
        lines.append(f"\n{idx}. Tool Name: `{c.tool_name}` {tier_symbol} [{c.risk_tier.upper()}]")
        lines.append(f"   Exposed By:     {', '.join(c.servers)} ({', '.join(c.packages)})")
        lines.append(f"   Schema Match:   {'IDENTICAL' if c.schema_identical else 'DIVERGENT'}")
        if c.risk_indicators:
            lines.append(f"   Risk Factors:   {', '.join(c.risk_indicators)}")
        if c.divergence_details:
            lines.append(f"   Divergence:     {c.divergence_details}")

    lines.append("--------------------------------------------------")
    lines.append("RECOMMENDATIONS:")
    if report.has_critical_conflicts:
        lines.append(" - CRITICAL: High-risk tools are being shadowed or duplicated across servers.")
        lines.append("   Rename tools in your server definitions or prefix tool names to prevent prompt injection hijacking.")
    else:
        lines.append(" - Review duplicate tool names to ensure your LLM client routes calls to the intended backend.")
    lines.append("==================================================")

    return "\n".join(lines)


class ConflictDetector:
    """Class wrapper for backward compatibility."""

    def __init__(self, matcher: Any | None = None):
        self.matcher = matcher

    def detect_conflicts(
        self,
        config_data: dict[str, Any] | None = None,
        servers: list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        report = audit_client_config(config_data or {})
        return [
            {
                "tool_name": c.tool_name,
                "servers": c.servers,
                "packages": c.packages,
                "schema_identical": c.schema_identical,
                "risk_tier": c.risk_tier,
                "risk_indicators": c.risk_indicators,
                "divergence_details": c.divergence_details,
            }
            for c in report.collisions
        ]

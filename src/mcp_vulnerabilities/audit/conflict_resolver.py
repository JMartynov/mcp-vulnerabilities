"""Automated Multi-Server Conflict Resolver."""

from __future__ import annotations

import copy
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.audit.conflict_detector import audit_client_config

logger = logging.getLogger("mcp_vulnerabilities.audit.conflict_resolver")


@dataclass
class ResolveResult:
    """The result of resolving conflicts in an MCP client configuration."""

    original_config: dict[str, Any]
    resolved_config: dict[str, Any]
    strategy_used: str
    modifications_made: list[str]
    audit_report: Any


def resolve_client_config(
    config_path: Path | str,
    strategy: str = "prefix",
    output_path: Path | str | None = None,
    passports_dir: Path | str = "data/fingerprints",
) -> ResolveResult:
    """
    Ingest a client configuration, resolve collisions by auto-namespacing conflicting
    tool names or rewriting server arguments, and output a sanitized client config.
    """
    config_p = Path(config_path)
    if not config_p.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_p}")

    original_config = json.loads(config_p.read_text(encoding="utf-8"))
    resolved_config = copy.deepcopy(original_config)
    modifications_made: list[str] = []

    # Run audit to identify collisions
    audit_report = audit_client_config(original_config, passports_dir=passports_dir)

    # Normalize accessing the servers configuration based on standard schemas
    servers_key = None
    if "mcpServers" in resolved_config and isinstance(
        resolved_config["mcpServers"], dict
    ):
        servers_key = "mcpServers"
    elif "context_servers" in resolved_config and isinstance(
        resolved_config["context_servers"], dict
    ):
        servers_key = "context_servers"

    if strategy == "report":
        # Do not modify the configuration, just report.
        pass
    elif not audit_report.is_clean and servers_key:
        servers_dict = resolved_config[servers_key]

        if strategy == "prefix":
            for collision in audit_report.collisions:
                for server in collision.servers:
                    if server not in servers_dict:
                        continue

                    s_conf = servers_dict[server]
                    if "env" not in s_conf:
                        s_conf["env"] = {}

                    env_key = f"MCP_PREFIX_{collision.tool_name.upper()}"
                    env_val = f"{server}__"

                    if env_key not in s_conf["env"]:
                        s_conf["env"][env_key] = env_val
                        modifications_made.append(
                            f"Set environment {env_key}={env_val} on server '{server}' to namespace tool '{collision.tool_name}'"
                        )

                    if "disabledTools" not in s_conf:
                        s_conf["disabledTools"] = []

                    prefix_arg = f"--prefix={server}__"
                    if (
                        isinstance(s_conf.get("args"), list)
                        and prefix_arg not in s_conf["args"]
                    ):
                        s_conf["args"].append(prefix_arg)
                        modifications_made.append(
                            f"Appended arg {prefix_arg} on server '{server}'"
                        )

        elif strategy == "priority":
            for collision in audit_report.collisions:
                if len(collision.servers) > 1:
                    winner = collision.servers[0]
                    losers = collision.servers[1:]
                    for loser in losers:
                        if loser not in servers_dict:
                            continue
                        s_conf = servers_dict[loser]
                        if "disabledTools" not in s_conf:
                            s_conf["disabledTools"] = []
                        if collision.tool_name not in s_conf["disabledTools"]:
                            s_conf["disabledTools"].append(collision.tool_name)
                            modifications_made.append(
                                f"Disabled tool '{collision.tool_name}' on server '{loser}' (Priority given to '{winner}')"
                            )

    elif not audit_report.is_clean and not servers_key:
        logger.warning(
            "Could not identify a valid servers configuration format to apply resolutions."
        )

    result = ResolveResult(
        original_config=original_config,
        resolved_config=resolved_config,
        strategy_used=strategy,
        modifications_made=modifications_made,
        audit_report=audit_report,
    )

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(resolved_config, indent=2) + "\n", encoding="utf-8")

    return result

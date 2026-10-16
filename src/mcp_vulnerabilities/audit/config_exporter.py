"""Config Exporter module for generating Claude Desktop, Cursor, Zed, Cline, Windsurf, and Docker client configurations."""

from __future__ import annotations

import json
import re
from typing import Any

SUPPORTED_CLIENTS = ("claude", "cursor", "cline", "zed", "windsurf", "docker")


def patch_jsonc(
    config_str: str, root_key: str, server_name: str, server_config: dict[str, Any]
) -> str:
    """
    Safely patch JSONC client configs by string injection to preserve comments.
    """
    if not config_str or not config_str.strip():
        config_str = "{}"

    server_json_lines = json.dumps(server_config, indent=2).split("\n")
    indented_server_json = "\n".join(
        "      " + line if i > 0 else line for i, line in enumerate(server_json_lines)
    )
    inner_block = f'"{server_name}": {indented_server_json}'

    match = re.search(rf'"{re.escape(root_key)}"\s*:\s*{{', config_str)
    if match:
        pos = match.end()
        after_brace = config_str[pos:]
        if re.match(r"\s*\}", after_brace):
            insertion = f"\n      {inner_block}\n    "
        else:
            insertion = f"\n      {inner_block},\n    "
        return config_str[:pos] + insertion + config_str[pos:]
    else:
        last_brace_idx = config_str.rfind("}")
        if last_brace_idx == -1:
            return (
                config_str
                + f'\n{{\n  "{root_key}": {{\n    {inner_block}\n  }}\n}}\n'
            )

        prev_chars = config_str[:last_brace_idx].strip()
        needs_comma = False
        if (
            prev_chars
            and not prev_chars.endswith("{")
            and not prev_chars.endswith(",")
        ):
            needs_comma = True

        insertion_parts = []
        if needs_comma:
            insertion_parts.append(",")

        insertion_parts.append(f'\n  "{root_key}": {{\n    {inner_block}\n  }}\n')

        insertion = "".join(insertion_parts)
        return config_str[:last_brace_idx] + insertion + config_str[last_brace_idx:]


class ConfigExporter:
    @classmethod
    def get_root_key(cls) -> str:
        raise NotImplementedError

    @classmethod
    def generate_server_config(cls, base_config: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    @classmethod
    def patch_config(
        cls, existing_jsonc: str, server_name: str, base_config: dict[str, Any]
    ) -> str:
        server_config = cls.generate_server_config(base_config)
        root_key = cls.get_root_key()
        return patch_jsonc(existing_jsonc, root_key, server_name, server_config)


class ZedExporter(ConfigExporter):
    @classmethod
    def get_root_key(cls) -> str:
        return "context_servers"

    @classmethod
    def generate_server_config(cls, base_config: dict[str, Any]) -> dict[str, Any]:
        if base_config.get("type") == "sse":
            server_conf: dict[str, Any] = {"url": base_config.get("url", "")}
            if base_config.get("headers"):
                server_conf["headers"] = base_config["headers"]
            return server_conf

        cmd_obj: dict[str, Any] = {
            "path": base_config.get("command", ""),
            "args": base_config.get("args", []),
        }
        if base_config.get("env"):
            cmd_obj["env"] = base_config["env"]
        return {"command": cmd_obj}


class ClineExporter(ConfigExporter):
    @classmethod
    def get_root_key(cls) -> str:
        return "mcpServers"

    @classmethod
    def generate_server_config(cls, base_config: dict[str, Any]) -> dict[str, Any]:
        server_conf = base_config.copy()
        server_conf.pop("type", None)
        if base_config.get("type") == "sse":
            server_conf["type"] = "sse"

        server_conf["disabled"] = False
        server_conf["autoApprove"] = []
        return server_conf


class WindsurfExporter(ConfigExporter):
    @classmethod
    def get_root_key(cls) -> str:
        return "mcpServers"

    @classmethod
    def generate_server_config(cls, base_config: dict[str, Any]) -> dict[str, Any]:
        server_conf = base_config.copy()
        server_conf.pop("type", None)
        if base_config.get("type") == "sse":
            server_conf["type"] = "sse"
        return server_conf


class ClaudeExporter(ConfigExporter):
    @classmethod
    def get_root_key(cls) -> str:
        return "mcpServers"

    @classmethod
    def generate_server_config(cls, base_config: dict[str, Any]) -> dict[str, Any]:
        server_conf = base_config.copy()
        server_conf.pop("type", None)
        if base_config.get("type") == "sse":
            server_conf["type"] = "sse"
        return server_conf


class CursorExporter(ConfigExporter):
    @classmethod
    def get_root_key(cls) -> str:
        return "mcpServers"

    @classmethod
    def generate_server_config(cls, base_config: dict[str, Any]) -> dict[str, Any]:
        server_conf = base_config.copy()
        server_conf.pop("type", None)
        if base_config.get("type") == "sse":
            server_conf["type"] = "sse"
        return server_conf


class DockerExporter(ConfigExporter):
    @classmethod
    def get_root_key(cls) -> str:
        return "docker"

    @classmethod
    def generate_server_config(cls, base_config: dict[str, Any]) -> dict[str, Any]:
        return base_config.copy()


def extract_base_config(passport: dict[str, Any]) -> dict[str, Any]:
    package_name = passport.get("package_name", "unknown")
    ecosystem = passport.get("ecosystem", "unknown")

    versions = passport.get("versions", [])
    if not versions:
        raise ValueError("Passport has no versions.")

    latest_version = versions[0]
    for v in versions:
        if v.get("connections"):
            latest_version = v
            break

    connections = latest_version.get("connections", [])

    conn = None
    if connections:
        for c in connections:
            if c.get("type") in ("stdio", "sse"):
                conn = c
                break
        if not conn:
            conn = connections[0]

    base_config: dict[str, Any] = {}
    if conn and conn.get("type") == "sse":
        base_config["type"] = "sse"
        base_config["url"] = (
            conn.get("url")
            or conn.get("deploymentUrl")
            or passport.get("remote_endpoint")
            or ""
        )
        if passport.get("headers_schema"):
            base_config["headers"] = passport.get("headers_schema")
    else:
        command = ""
        args = []
        env = {}

        if conn and conn.get("type") == "stdio":
            command = conn.get("command", "")
            args = conn.get("args", [])
            env = conn.get("env", {})

        if not command:
            if ecosystem == "npm":
                command = "npx"
                args = ["-y", package_name] + args
            elif ecosystem == "pypi":
                command = "uvx"
                args = [package_name] + args
            else:
                command = package_name

        base_config["type"] = "stdio"
        base_config["command"] = command
        base_config["args"] = args
        if env:
            base_config["env"] = env

    return base_config


EXPORTER_MAP = {
    "claude": ClaudeExporter,
    "cursor": CursorExporter,
    "cline": ClineExporter,
    "zed": ZedExporter,
    "windsurf": WindsurfExporter,
}


def export_client_config(passport: dict[str, Any], client: str = "claude") -> dict[str, Any]:
    """Format client configuration for 'claude', 'cursor', 'cline', 'zed', 'windsurf', or 'docker'."""
    if client not in SUPPORTED_CLIENTS:
        raise ValueError(
            f"Unsupported client: {client}. Must be one of {SUPPORTED_CLIENTS}."
        )

    package_name = passport.get("package_name", "unknown")
    safe_name = package_name.replace("@", "").replace("/", "-").replace("_", "-")
    base_config = extract_base_config(passport)

    if client == "docker":
        if base_config.get("type") == "sse":
            return {
                "sseUrl": base_config.get("url", ""),
                "note": "SSE connection does not require local container execution.",
            }
        ecosystem = passport.get("ecosystem", "unknown")
        if ecosystem == "npm":
            image = "node:22-alpine"
        elif ecosystem == "pypi":
            image = "python:3.12-slim"
        else:
            image = "alpine:latest"

        cmd_parts = ["docker", "run", "-i", "--rm"]
        for k, v in base_config.get("env", {}).items():
            cmd_parts.extend(["-e", f"{k}={v}"])
        cmd_parts.append(image)
        cmd_parts.append(base_config.get("command", ""))
        cmd_parts.extend(base_config.get("args", []))

        return {
            "dockerCommand": " ".join(cmd_parts),
            "container": {
                "image": image,
                "command": base_config.get("command", ""),
                "args": base_config.get("args", []),
                "env": base_config.get("env", {}),
            },
        }

    exporter_cls = EXPORTER_MAP[client]
    root_key = exporter_cls.get_root_key()
    server_conf = exporter_cls.generate_server_config(base_config)
    return {root_key: {safe_name: server_conf}}


def export_all_client_configs(passport: dict[str, Any]) -> dict[str, Any]:
    """Export client configurations across all supported clients."""
    return {c: export_client_config(passport, client=c) for c in SUPPORTED_CLIENTS}

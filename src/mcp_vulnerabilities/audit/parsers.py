"""Parsers for extracting MCP server definitions and versions from AI client configurations."""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_fingerprints.config_scanner import ConfigScanner, NpmGlobalScanner

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredClientServer:
    server_name: str
    package_name: str
    version: str | None
    ecosystem: str | None
    command: str
    args: list[str]
    source_file: Path | None = None
    client_name: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    declared_tools: list[dict[str, Any]] = field(default_factory=list)


class ClientConfigParser:
    """Parses various AI client configuration formats to extract MCP server definitions."""

    @staticmethod
    def get_standard_config_paths() -> list[Path]:
        """Returns standard locations for Claude Desktop and other AI client MCP configs."""
        home = Path.home()
        paths = [
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            home / ".config" / "Claude" / "claude_desktop_config.json",
            Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json" if os.environ.get("APPDATA") else None,
            home / ".cursor" / "mcp.json",
            home / ".claude.json",
            home / ".config" / "zed" / "settings.json",
            home / ".codeium" / "windsurf" / "mcp_config.json",
        ]
        return [p for p in paths if p and p.exists() and p.is_file()]

    @classmethod
    def parse_file(cls, path: Path, client_name: str | None = None) -> list[DiscoveredClientServer]:
        """Parses a specific client config file (JSON, JSONC, or YAML)."""
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        text = path.read_text(encoding="utf-8")
        # Handle trailing commas or comments if needed
        clean_text = re.sub(r"//.*", "", text)
        clean_text = re.sub(r",\s*([\]}])", r"\1", clean_text)

        data = None
        try:
            data = json.loads(clean_text)
        except Exception:
            try:
                import yaml
                data = yaml.safe_load(text)
            except Exception as e:
                logger.warning(f"Could not parse config file {path}: {e}")
                return []

        if not isinstance(data, dict):
            return []

        return cls.parse_dict(data, source_file=path, client_name=client_name)

    @classmethod
    def parse_dict(
        cls,
        data: dict[str, Any],
        source_file: Path | None = None,
        client_name: str | None = None,
    ) -> list[DiscoveredClientServer]:
        """Parses a loaded config dictionary containing server configurations."""
        servers: list[DiscoveredClientServer] = []
        raw_servers = (
            data.get("mcpServers")
            or data.get("mcp_servers")
            or data.get("context_servers")
            or data.get("servers")
        )

        if not isinstance(raw_servers, dict):
            # Check if root itself is a dictionary of server configs
            if all(isinstance(v, dict) and ("command" in v or "args" in v) for v in data.values()):
                raw_servers = data
            else:
                return servers

        for name, srv_conf in raw_servers.items():
            if not isinstance(srv_conf, dict):
                continue
            parsed = cls._parse_server_entry(name, srv_conf, source_file, client_name=client_name)
            if parsed:
                servers.append(parsed)

        return servers

    @classmethod
    def _parse_server_entry(
        cls,
        name: str,
        conf: dict[str, Any],
        source_file: Path | None = None,
        client_name: str | None = None,
    ) -> DiscoveredClientServer | None:
        command_val = conf.get("command", "")
        if isinstance(command_val, dict):
            # Zed context_servers format: command: { path: "...", args: [...] }
            cmd_path = command_val.get("path") or command_val.get("command", "")
            command = str(cmd_path).strip()
            args = [str(a) for a in command_val.get("args", conf.get("args", []))]
            env = command_val.get("env", conf.get("env", {}))
        else:
            command = str(command_val).strip()
            args = [str(a) for a in conf.get("args", [])]
            env = conf.get("env", {})

        if not isinstance(env, dict):
            env = {}

        if not command and not args:
            return None

        cmd_lower = Path(command).name.lower()
        package_name = name
        version: str | None = None
        ecosystem: str | None = None

        if cmd_lower in ("npx", "pnpx", "bunx"):
            ecosystem = "npm"
            for arg in args:
                if arg.startswith("-"):
                    continue
                pkg, ver = cls._extract_npm_package_and_version(arg)
                package_name = pkg
                version = ver
                break

        elif cmd_lower in ("uvx", "pipx"):
            ecosystem = "PyPI"
            for arg in args:
                if arg.startswith("-"):
                    continue
                pkg, ver = cls._extract_python_package_and_version(arg)
                package_name = pkg
                version = ver
                break

        elif cmd_lower in ("python", "python3"):
            ecosystem = "PyPI"
            for i, arg in enumerate(args):
                if arg == "-m" and i + 1 < len(args):
                    mod = args[i + 1]
                    package_name = mod.replace("_", "-")
                    break

        elif cmd_lower == "node":
            ecosystem = "npm"
            for arg in args:
                if not arg.startswith("-"):
                    package_name = Path(arg).stem
                    break

        elif cmd_lower == "docker":
            ecosystem = "Docker"
            for arg in reversed(args):
                if not arg.startswith("-") and arg not in ("run", "exec", "container"):
                    if ":" in arg:
                        pkg, ver = arg.rsplit(":", 1)
                        package_name = pkg
                        version = ver
                    else:
                        package_name = arg
                    break

        declared_tools = conf.get("tools", command_val.get("tools", []) if isinstance(command_val, dict) else [])
        if not isinstance(declared_tools, list):
            declared_tools = []
            
        return DiscoveredClientServer(
            server_name=name,
            package_name=package_name,
            version=version,
            ecosystem=ecosystem,
            command=command,
            args=args,
            source_file=source_file,
            client_name=client_name,
            env=env,
            declared_tools=declared_tools,
        )

    @staticmethod
    def _extract_npm_package_and_version(spec: str) -> tuple[str, str | None]:
        spec = spec.strip()
        if spec.startswith("@"):
            parts = spec[1:].split("@", 1)
            pkg = f"@{parts[0]}"
            ver = parts[1] if len(parts) > 1 else None
            return pkg, ver
        else:
            parts = spec.split("@", 1)
            pkg = parts[0]
            ver = parts[1] if len(parts) > 1 else None
            return pkg, ver

    @staticmethod
    def _extract_python_package_and_version(spec: str) -> tuple[str, str | None]:
        spec = spec.strip()
        match = re.split(r"(==|>=|<=|>|<|~=|@)", spec, maxsplit=1)
        pkg = match[0].strip()
        ver = match[2].strip() if len(match) > 2 else None
        return pkg, ver


class UniversalClientConfigScanner:
    """Discovers and parses MCP configurations across 9 AI clients + global npm/npx packages."""

    SUPPORTED_CLIENTS = (
        "claude",
        "cursor",
        "vscode",
        "zed",
        "cline",
        "windsurf",
        "continue",
        "librechat",
        "openwebui",
    )

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path.home()
        self.config_scanner = ConfigScanner()
        self.global_scanner = NpmGlobalScanner()

    def get_client_paths(self, client_name: str) -> list[Path]:
        c = client_name.lower()
        if c == "claude":
            return [
                self.root / "Library/Application Support/Claude/claude_desktop_config.json",
                self.root / ".config/Claude/claude_desktop_config.json",
                self.root / ".claude.json",
                self.root / ".claude/config.json",
            ]
        elif c == "cursor":
            return [
                self.root / ".cursor/mcp.json",
                self.root / ".cursorrules",
            ]
        elif c == "vscode":
            return [
                self.root / "Library/Application Support/Code/User/settings.json",
                self.root / ".config/Code/User/settings.json",
                self.root / ".vscode/mcp.json",
            ]
        elif c == "zed":
            return [
                self.root / ".config/zed/settings.json",
                self.root / "Library/Application Support/Zed/settings.json",
            ]
        elif c == "cline":
            return [
                self.root / "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
                self.root / ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
            ]
        elif c == "windsurf":
            return [
                self.root / ".codeium/windsurf/mcp_config.json",
            ]
        elif c == "continue":
            return [
                self.root / ".continue/config.json",
                self.root / ".continue/config.yaml",
            ]
        elif c == "librechat":
            return [
                self.root / ".librechat/librechat.yaml",
                self.root / "librechat.yaml",
            ]
        elif c == "openwebui":
            return [
                self.root / ".openwebui/config.json",
            ]
        return []

    def scan_client(self, client_name: str) -> list[DiscoveredClientServer]:
        servers: list[DiscoveredClientServer] = []
        paths = self.get_client_paths(client_name)
        for p in paths:
            if p and p.is_file():
                try:
                    res = ClientConfigParser.parse_file(p, client_name=client_name)
                    servers.extend(res)
                except Exception as e:
                    logger.debug(f"Error scanning {client_name} at {p}: {e}")
        return servers

    def scan_all_clients(self) -> list[DiscoveredClientServer]:
        all_servers: list[DiscoveredClientServer] = []
        for client in self.SUPPORTED_CLIENTS:
            all_servers.extend(self.scan_client(client))
        return all_servers

    def scan_global(self) -> list[DiscoveredClientServer]:
        """Discovers globally installed npm and npx cached MCP servers."""
        discovered: list[DiscoveredClientServer] = []
        try:
            raw_global = self.global_scanner.scan_global_npm()
            for item in raw_global:
                pkg_name = item.get("package_name", item.get("name", ""))
                version = item.get("version")
                source = item.get("source", "global_npm")
                discovered.append(
                    DiscoveredClientServer(
                        server_name=pkg_name,
                        package_name=pkg_name,
                        version=version,
                        ecosystem="npm",
                        command="npx",
                        args=[f"{pkg_name}@{version}"] if version else [pkg_name],
                        source_file=Path(item.get("path", source)),
                        client_name="global_npm",
                    )
                )
        except Exception as e:
            logger.debug(f"Error in scan_global: {e}")
        return discovered

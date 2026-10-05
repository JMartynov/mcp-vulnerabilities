"""Parsers for extracting MCP server definitions and versions from AI client configurations."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional


@dataclass
class DiscoveredClientServer:
    server_name: str
    package_name: str
    version: Optional[str]
    ecosystem: Optional[str]
    command: str
    args: List[str]
    source_file: Optional[Path] = None


class ClientConfigParser:
    """Parses various AI client configuration formats to extract MCP server definitions."""

    @staticmethod
    def get_standard_config_paths() -> List[Path]:
        """Returns standard locations for Claude Desktop and other AI client MCP configs."""
        home = Path.home()
        paths = [
            # macOS Claude Desktop
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            # Linux Claude Desktop
            home / ".config" / "Claude" / "claude_desktop_config.json",
            # Windows Claude Desktop (via APPDATA if present)
            Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json" if os.environ.get("APPDATA") else None,
            # Cursor MCP config
            home / ".cursor" / "mcp.json",
            # Claude Code project / global config
            home / ".claude.json",
        ]
        return [p for p in paths if p and p.exists() and p.is_file()]

    @classmethod
    def parse_file(cls, path: Path) -> List[DiscoveredClientServer]:
        """Parses a specific client config JSON file."""
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return cls.parse_dict(data, source_file=path)

    @classmethod
    def parse_dict(cls, data: Dict[str, Any], source_file: Optional[Path] = None) -> List[DiscoveredClientServer]:
        """Parses a loaded config dictionary containing server configurations."""
        servers: List[DiscoveredClientServer] = []
        raw_servers = data.get("mcpServers") or data.get("mcp_servers") or data.get("servers")

        if not isinstance(raw_servers, dict):
            # Check if root itself is a dictionary of server configs
            if all(isinstance(v, dict) and ("command" in v or "args" in v) for v in data.values()):
                raw_servers = data
            else:
                return servers

        for name, srv_conf in raw_servers.items():
            if not isinstance(srv_conf, dict):
                continue
            parsed = cls._parse_server_entry(name, srv_conf, source_file)
            if parsed:
                servers.append(parsed)

        return servers

    @classmethod
    def _parse_server_entry(
        cls,
        name: str,
        conf: Dict[str, Any],
        source_file: Optional[Path] = None,
    ) -> Optional[DiscoveredClientServer]:
        command = str(conf.get("command", "")).strip()
        args = [str(a) for a in conf.get("args", [])]

        if not command and not args:
            return None

        cmd_lower = Path(command).name.lower()
        package_name = name
        version: Optional[str] = None
        ecosystem: Optional[str] = None

        if cmd_lower in ("npx", "pnpx", "bunx"):
            ecosystem = "npm"
            # Extract target package from arguments, skipping flags like -y, --yes, etc.
            for arg in args:
                if arg.startswith("-"):
                    continue
                # Found package spec: e.g. @modelcontextprotocol/server-neo4j@0.6.1 or server-neo4j@0.6.1
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
            # Check for -m <module>
            for i, arg in enumerate(args):
                if arg == "-m" and i + 1 < len(args):
                    mod = args[i + 1]
                    package_name = mod.replace("_", "-")
                    break

        elif cmd_lower == "node":
            ecosystem = "npm"
            # Could be a script path
            for arg in args:
                if not arg.startswith("-"):
                    package_name = Path(arg).stem
                    break

        elif cmd_lower == "docker":
            ecosystem = "Docker"
            # docker run ... image:tag
            for arg in reversed(args):
                if not arg.startswith("-") and arg not in ("run", "exec", "container"):
                    if ":" in arg:
                        pkg, ver = arg.rsplit(":", 1)
                        package_name = pkg
                        version = ver
                    else:
                        package_name = arg
                    break

        return DiscoveredClientServer(
            server_name=name,
            package_name=package_name,
            version=version,
            ecosystem=ecosystem,
            command=command,
            args=args,
            source_file=source_file,
        )

    @staticmethod
    def _extract_npm_package_and_version(spec: str) -> tuple[str, Optional[str]]:
        """Parses npm package specifiers like `@scope/name@1.0.0` or `name@^2.0`."""
        spec = spec.strip()
        if spec.startswith("@"):
            # Scoped package: @scope/pkg or @scope/pkg@version
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
    def _extract_python_package_and_version(spec: str) -> tuple[str, Optional[str]]:
        """Parses Python package specifiers like `mcp-server-git==0.1.0` or `mcp-server-git>=0.2.0`."""
        spec = spec.strip()
        match = re.split(r"(==|>=|<=|>|<|~=|@)", spec, maxsplit=1)
        pkg = match[0].strip()
        ver = match[2].strip() if len(match) > 2 else None
        return pkg, ver

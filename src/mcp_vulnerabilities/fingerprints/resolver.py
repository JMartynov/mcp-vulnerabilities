"""Fingerprint-based version resolver for unpinned and dynamic MCP servers."""

from __future__ import annotations

import json
import logging
import os
import re
import select
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp_fingerprints.config_scanner import NpmGlobalScanner

if TYPE_CHECKING:
    from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer

logger = logging.getLogger(__name__)


class FingerprintVersionResolver:
    """Resolves concrete installed/cached versions for unpinned MCP servers using mcp-fingerprints."""

    def __init__(self, passports_path: Path | str | None = None) -> None:
        self.npm_scanner = NpmGlobalScanner()
        self.passports_path = Path(passports_path) if passports_path else None
        self._npx_cache: list[dict[str, Any]] | None = None
        self._passport_matcher: Any = None
        self._memo: dict[tuple[str, tuple[str, ...], str], tuple[str | None, str | None]] = {}

    def _get_npx_items(self) -> list[dict[str, Any]]:
        """Scans and caches npx and global npm packages ordered by modification time."""
        if self._npx_cache is None:
            items: list[dict[str, Any]] = []
            try:
                items.extend(self.npm_scanner.scan_npx_cache())
            except Exception as e:
                logger.debug("Failed scanning npx cache: %s", e)
            try:
                items.extend(self.npm_scanner.scan_global_npm())
            except Exception as e:
                logger.debug("Failed scanning global npm: %s", e)

            def get_mtime(item: dict[str, Any]) -> float:
                p = item.get("source")
                try:
                    return os.path.getmtime(p) if p and os.path.exists(p) else 0.0
                except Exception:
                    return 0.0

            items.sort(key=get_mtime, reverse=True)
            self._npx_cache = items
        return self._npx_cache

    def _get_passport_matcher(self) -> Any:
        """Lazily loads the FingerprintMatcher for passport database lookups."""
        if self._passport_matcher is None:
            try:
                from mcp_fingerprints.matcher import FingerprintMatcher
                matcher = FingerprintMatcher()
                if self.passports_path and self.passports_path.exists():
                    matcher.load_from_snapshot(self.passports_path)
                else:
                    matcher.load_default()
                self._passport_matcher = matcher
            except Exception as e:
                logger.debug("Could not load FingerprintMatcher: %s", e)
                self._passport_matcher = False
        return self._passport_matcher if self._passport_matcher is not False else None

    def resolve_server_version(
        self, server: DiscoveredClientServer
    ) -> tuple[str | None, str | None]:
        """Resolves the concrete version and resolution source for an MCP server."""
        memo_key = (server.command, tuple(server.args), server.package_name)
        if memo_key in self._memo:
            return self._memo[memo_key]

        res = self._resolve_uncached(server)
        self._memo[memo_key] = res
        return res

    def _resolve_uncached(
        self, server: DiscoveredClientServer
    ) -> tuple[str | None, str | None]:
        # 1. NPX / Global NPM cache inspection
        npx_items = self._get_npx_items()
        candidate_names = {server.package_name.lower()}
        for arg in server.args:
            clean_arg = arg.split("@")[0].lower()
            if not clean_arg.startswith("-"):
                candidate_names.add(clean_arg)
                if "/" in clean_arg:
                    candidate_names.add(clean_arg.split("/")[-1])

        for it in npx_items:
            name = (it.get("name") or "").lower()
            ver = it.get("version")
            if not name or not ver:
                continue
            if name in candidate_names or any(c in name for c in candidate_names if len(c) > 3):
                src = "npx-cache" if it.get("client") == "npx-cache" else "npm-global"
                return ver, src

        # 2. Node.js script package.json traversal
        for arg in server.args:
            p = Path(arg)
            if p.suffix in (".js", ".mjs", ".cjs", ".ts") and p.exists():
                for parent in p.parents:
                    pj = parent / "package.json"
                    if pj.exists():
                        try:
                            d = json.loads(pj.read_text(encoding="utf-8"))
                            if "version" in d and d["version"]:
                                return str(d["version"]), "package.json"
                        except Exception:
                            pass

        # 3. Python virtualenv and project inspection
        if server.command and ("python" in Path(server.command).name.lower() or "python" in server.command.lower()):
            cmd_p = Path(server.command)
            search_dirs: list[Path] = []
            if "PYTHONPATH" in server.env:
                for pth in server.env["PYTHONPATH"].split(os.pathsep):
                    if pth:
                        sp_p = Path(pth)
                        search_dirs.append(sp_p)
                        search_dirs.append(sp_p.parent)
            for parent in cmd_p.parents:
                search_dirs.append(parent)
                if (parent / "pyvenv.cfg").exists():
                    search_dirs.extend(parent.glob("lib/python*/site-packages"))

            for d in search_dirs:
                if not d.exists():
                    continue
                # Check pyproject.toml
                pj = d / "pyproject.toml"
                if pj.exists():
                    try:
                        txt = pj.read_text(encoding="utf-8")
                        m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', txt)
                        if m:
                            return m.group(1), "pyproject.toml"
                    except Exception:
                        pass
                # Check .dist-info
                for dist in d.glob("*.dist-info"):
                    dist_name = dist.name.rsplit(".dist-info", 1)[0]
                    if "-" in dist_name:
                        pname, pver = dist_name.rsplit("-", 1)
                        clean_target = server.server_name.lower().replace("_", "-").split("-")[0]
                        if clean_target in pname.lower():
                            return pver, "dist-info"

        # 4. Live MCP Handshake (initialize)
        if server.command:
            try:
                cmd = [server.command] + server.args
                env = os.environ.copy()
                env.update(server.env)
                p = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                )
                req = (
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {
                                    "name": "mcp-vuln-audit",
                                    "version": "1.0.0",
                                },
                            },
                        }
                    )
                    + "\n"
                )
                p.stdin.write(req)
                p.stdin.flush()
                rlist, _, _ = select.select([p.stdout], [], [], 1.5)
                if rlist and p.stdout:
                    line = p.stdout.readline()
                    data = json.loads(line)
                    srv_info = data.get("result", {}).get("serverInfo", {})
                    v = srv_info.get("version")
                    if v:
                        clean_v = re.sub(r"^[a-zA-Z\-_]+", "", str(v)).strip()
                        p.terminate()
                        return clean_v or str(v), "handshake"
                p.terminate()
            except Exception:
                pass

        # 5. Passports match fallback
        passport_matcher = self._get_passport_matcher()
        if passport_matcher and hasattr(passport_matcher, "fast_index"):
            spec = passport_matcher.fast_index.find_package_by_hint_or_alias(server.package_name)
            if spec and spec.versions:
                latest_v = spec.versions[-1].version
                return latest_v, "passport"

        return None, None

    def enrich_servers(
        self, servers: list[DiscoveredClientServer]
    ) -> list[DiscoveredClientServer]:
        """Enriches servers with detected versions where version was unpinned or missing."""
        for s in servers:
            if not s.version or s.version in ("unpinned", "latest", "*"):
                res_ver, res_src = self.resolve_server_version(s)
                if res_ver:
                    s.original_version = s.version
                    s.version = res_ver
                    s.resolution_source = res_src
        return servers

"""npm Registry discovery provider for MCP servers."""

from __future__ import annotations

import json
import logging
import ssl
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta
from typing import Any

from mcp_vulnerabilities.filter import McpRelevanceFilter
from mcp_vulnerabilities.ssl_utils import get_ssl_context

logger = logging.getLogger("mcp_vulnerabilities.discovery.npm")


def _get_ssl_context() -> ssl.SSLContext:
    return get_ssl_context()


class NpmDiscoveryProvider:
    """Discovers Model Context Protocol packages published on npm."""

    DEFAULT_QUERIES: tuple[str, ...] = (
        "keywords:mcp-server",
        "keywords:modelcontextprotocol",
        "text=@modelcontextprotocol",
        "mcp-server",
    )

    @staticmethod
    def should_skip_due_to_backoff(endpoint: str, state: dict, current_time: datetime | None = None) -> bool:
        """Evaluate exponential backoff logic for offline endpoints."""
        if not state:
            return False

        endpoint_state = state.get(endpoint, {})
        consecutive_failures = endpoint_state.get("consecutive_failures", 0)

        if consecutive_failures == 0:
            return False

        next_retry_after_str = endpoint_state.get("next_retry_after")
        if not next_retry_after_str:
            return False

        if current_time is None:
            current_time = datetime.now(timezone.utc)

        try:
            # Handle formats with or without Z
            if next_retry_after_str.endswith('Z'):
                next_retry_after_str = next_retry_after_str[:-1] + '+00:00'
            next_retry_after = datetime.fromisoformat(next_retry_after_str)
            if next_retry_after.tzinfo is None:
                next_retry_after = next_retry_after.replace(tzinfo=timezone.utc)
        except ValueError:
            return False

        return current_time < next_retry_after

    @staticmethod
    def update_backoff_state(endpoint: str, state: dict, success: bool, current_time: datetime | None = None, base_hours: float = 1.0, max_backoff_days: float = 7.0) -> None:
        """Update backoff state for an endpoint."""
        if current_time is None:
            current_time = datetime.now(timezone.utc)

        if endpoint not in state:
            state[endpoint] = {}

        if success:
            state[endpoint]["consecutive_failures"] = 0
            state[endpoint]["next_retry_after"] = None
        else:
            failures = state[endpoint].get("consecutive_failures", 0) + 1
            state[endpoint]["consecutive_failures"] = failures

            # calculate backoff interval
            backoff_hours = base_hours * (2 ** (failures - 1))
            backoff_days = backoff_hours / 24.0
            actual_backoff_days = min(max_backoff_days, backoff_days)
            actual_backoff_hours = actual_backoff_days * 24.0

            next_retry = current_time + timedelta(hours=actual_backoff_hours)
            # Ensure RFC 3339 format with Z for UTC
            state[endpoint]["next_retry_after"] = next_retry.isoformat().replace("+00:00", "Z")

    @classmethod
    def discover(cls, queries: tuple[str, ...] | None = None, limit_per_query: int = 250, backoff_state: dict | None = None) -> list[dict[str, Any]]:
        """Query npm registry search API and return verified MCP server metadata."""
        search_terms = queries or cls.DEFAULT_QUERIES
        discovered: dict[str, dict[str, Any]] = {}

        if backoff_state is None:
            backoff_state = {}

        for q in search_terms:
            endpoint = "npmjs_search"
            if cls.should_skip_due_to_backoff(endpoint, backoff_state):
                logger.info("Skipping npm discovery query '%s' due to backoff.", q)
                continue

            url = f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(q)}&size={limit_per_query}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "McpVulnerabilities/1.0", "Accept": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=12.0, context=_get_ssl_context()) as resp:
                    cls.update_backoff_state(endpoint, backoff_state, success=True)
                    data = json.loads(resp.read().decode("utf-8"))
                    for obj in data.get("objects", []):
                        pkg = obj.get("package", {})
                        name = pkg.get("name")
                        if not name or name in discovered:
                            continue

                        desc = pkg.get("description", "")
                        repo = pkg.get("links", {}).get("repository")
                        version = pkg.get("version", "1.0.0")


                        # Normalize repository URL
                        if repo:
                            if repo.startswith("git://"):
                                repo = repo.replace("git://", "https://")
                            elif repo.startswith("git+ssh://"):
                                repo = repo.replace("git+ssh://", "https://")
                            elif repo.startswith("ssh://"):
                                repo = repo.replace("ssh://", "https://")
                            if repo.startswith("git+https://"):
                                repo = repo.replace("git+https://", "https://")
                            if repo.endswith(".git"):
                                repo = repo[:-4]

                        is_rel, reasons = McpRelevanceFilter.is_relevant(

                            package_name=name,
                            summary=desc,
                            details=desc,
                            repo_url=repo,
                        )
                        if is_rel:
                            # Fetch package metadata to check for deprecation
                            is_deprecated = False
                            deprecation_reason = ""
                            meta_url = f"https://registry.npmjs.org/{urllib.parse.quote(name)}"
                            meta_req = urllib.request.Request(
                                meta_url,
                                headers={"User-Agent": "McpVulnerabilities/1.0", "Accept": "application/json"},
                            )
                            try:
                                with urllib.request.urlopen(meta_req, timeout=5.0, context=_get_ssl_context()) as meta_resp:
                                    meta_data = json.loads(meta_resp.read().decode("utf-8"))
                                    # check latest version or overall package
                                    versions = meta_data.get("versions", {})
                                    latest_ver = meta_data.get("dist-tags", {}).get("latest")
                                    if latest_ver and latest_ver in versions:
                                        depr = versions[latest_ver].get("deprecated")
                                        if depr:
                                            is_deprecated = True
                                            deprecation_reason = str(depr)
                            except Exception as meta_exc:
                                logger.debug("Failed to fetch metadata for %s: %s", name, meta_exc)

                            discovered[name] = {
                                "name": name,
                                "ecosystem": "npm",
                                "version": version,
                                "description": desc,
                                "repository": repo,
                                "reasons": list(reasons),
                                "is_deprecated": is_deprecated,
                                "deprecation_reason": deprecation_reason,
                            }
            except Exception as exc:
                cls.update_backoff_state(endpoint, backoff_state, success=False)
                logger.warning("npm discovery query '%s' failed: %s", q, exc)

        return list(discovered.values())

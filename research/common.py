"""Common utilities and benchmarking helpers for empirical MCP research."""

from __future__ import annotations

import json
import logging
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("mcp_research")

DEFAULT_USER_AGENT = "McpVulnerabilitiesResearch/1.0 (Security Research; https://github.com/JMartynov/mcp-vulnerabilities)"

# SSL Context initialization for macOS python environments
try:
    ssl_context = ssl.create_default_context()
except Exception:
    ssl_context = ssl._create_unverified_context()

def get_ssl_context() -> ssl.SSLContext:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return ssl._create_unverified_context()



@dataclass
class ResearchMetric:
    method_name: str
    target_source: str
    items_scanned: int
    mcp_items_identified: int
    vulnerabilities_found: int
    duration_seconds: float
    error_count: int
    rate_limit_encountered: bool
    notes: str


def fetch_json(url: str, headers: dict[str, str] | None = None, timeout: float = 10.0, data: bytes | None = None) -> Any:
    """Safely fetch and parse JSON from a remote URL."""
    hdrs = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout, context=get_ssl_context()) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_text(url: str, headers: dict[str, str] | None = None, timeout: float = 10.0) -> str:
    """Safely fetch plain text / markdown from a remote URL."""
    hdrs = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout, context=get_ssl_context()) as resp:
        return resp.read().decode("utf-8")


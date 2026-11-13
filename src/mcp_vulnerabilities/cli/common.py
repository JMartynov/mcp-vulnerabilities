"""Common utilities, console, and logger for the CLI package."""

from __future__ import annotations

import logging
import re

try:
    from rich.console import Console

    console = Console()
except ImportError:
    import contextlib

    class FallbackConsole:
        def print(self, *args, **kwargs):
            clean_args = []
            for a in args:
                if isinstance(a, str):
                    clean_args.append(re.sub(r"\[/?[a-zA-Z0-9_ ]+\]", "", a))
                else:
                    clean_args.append(a)
            print(*clean_args)

        @contextlib.contextmanager
        def status(self, *args, **kwargs):
            yield

    console = FallbackConsole()

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("mcp_vulnerabilities.cli")

__all__ = ["console", "logger"]

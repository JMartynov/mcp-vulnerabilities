"""Handlers for daemon processes, TUI, monitor, bridge, and HTTP API server."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time

from mcp_vulnerabilities.api.server import McpSecurityApiServer
from mcp_vulnerabilities.cli.common import logger


def handle_serve(args: argparse.Namespace) -> None:
    host = os.environ.get("MCP_VULN_HOST", args.host)
    port_str = os.environ.get("MCP_VULN_PORT")
    port = int(port_str) if port_str else args.port

    server = McpSecurityApiServer(
        host=host,
        port=port,
        cors_origins=args.cors_origins,
    )

    shutdown_event = threading.Event()

    def sig_handler(signum, frame):
        logger.info(f"Received signal {signum}, stopping server...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    server.start()
    try:
        while not shutdown_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    sys.exit(0)


def handle_tui(args: argparse.Namespace) -> None:
    if not sys.stdin.isatty():
        print(
            "Error: Interactive TUI requires a TTY terminal. Use 'mcp-vuln audit' for headless output.",
            file=sys.stderr,
        )
        sys.exit(1)
    from mcp_vulnerabilities.audit.tui import launch_tui

    launch_tui(args)
    sys.exit(0)


def handle_monitor(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.daemon.monitor import start_monitor

    start_monitor(args)
    sys.exit(0)


def handle_bridge(args: argparse.Namespace) -> None:
    if args.host not in ["127.0.0.1", "::1"]:
        print(
            "Security error: Bridge daemon must bind to loopback address (127.0.0.1 or ::1).",
            file=sys.stderr,
        )
        sys.exit(2)
    from mcp_vulnerabilities.daemon.bridge import run_bridge_server

    run_bridge_server(args)
    sys.exit(0)

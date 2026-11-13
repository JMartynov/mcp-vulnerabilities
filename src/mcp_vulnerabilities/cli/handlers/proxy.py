"""Handler for reverse proxy command."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def handle_proxy(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.proxy.policy import ProxyPolicyEngine
    from mcp_vulnerabilities.proxy.interceptor import McpStdioProxy

    cmd_args = args.command_args
    if cmd_args and cmd_args[0] == "--":
        cmd_args = cmd_args[1:]

    if not cmd_args:
        print("Error: Must specify a command to wrap", file=sys.stderr)
        sys.exit(1)

    policy_engine = ProxyPolicyEngine(
        package_name=args.package,
        blocked_tools=set(args.blocked_tools),
        strict_passport=args.strict_passport,
        enable_payload_guardrails=args.enable_payload_guardrails,
        vulnerabilities_dir=Path(args.dir) if args.dir else None,
    )

    proxy = McpStdioProxy(
        policy_engine=policy_engine,
        mode=args.mode,
        audit_log_path=args.audit_log,
        sandbox=args.sandbox,
        canary_detection=args.canary_detection,
    )

    sys.exit(proxy.run_stdio(cmd_args))

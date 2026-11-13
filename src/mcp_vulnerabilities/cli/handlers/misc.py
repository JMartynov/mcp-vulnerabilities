"""Handlers for miscellaneous commands (linting and container sandboxing)."""

from __future__ import annotations

import argparse
import json
import sys

from mcp_vulnerabilities.analyzers import ReadinessLinter
from mcp_vulnerabilities.cli.common import logger
from mcp_vulnerabilities.probe.client import McpProbeClient
from mcp_vulnerabilities.probe.transport import HttpSseTransport, StdioTransport
from mcp_vulnerabilities.sandbox.engine import ContainerEngine
from mcp_vulnerabilities.sandbox.runner import EphemeralSandbox, TimeoutExpired


def handle_lint(args: argparse.Namespace) -> None:
    import mcp_vulnerabilities.cli as cli

    probe_client_cls = getattr(cli, "McpProbeClient", McpProbeClient)
    linter = ReadinessLinter()
    schema = []
    target_name = "unknown"

    if args.file:
        target_name = args.file
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                schema = json.load(f)
        except Exception as e:
            logger.error(f"Error reading schema file '{args.file}': {e}")
            sys.exit(1)
    elif args.server_command:
        target_name = args.server_command
        try:
            transport = StdioTransport(args.server_command)
            client = probe_client_cls(transport)
            client.connect_and_discover(timeout=5.0)
            schema = client.tools
        except Exception as e:
            logger.error(f"Error querying command '{args.server_command}': {e}")
            sys.exit(1)
    elif args.url:
        target_name = args.url
        try:
            transport = HttpSseTransport(args.url)
            client = probe_client_cls(transport)
            client.connect_and_discover(timeout=5.0)
            schema = client.tools
        except Exception as e:
            logger.error(f"Error querying URL '{args.url}': {e}")
            sys.exit(1)
    else:
        logger.error("Must provide either --file, --command, or --url to lint.")
        sys.exit(2)

    report = linter.lint_schema(schema, target_name=target_name)

    compliance_report = None
    if getattr(args, "compliance", None):
        from mcp_vulnerabilities.compliance.owasp import OwaspComplianceScorer

        compliance_report = OwaspComplianceScorer.evaluate(
            readiness_issues=report.issues
        )

    if args.format == "json":
        out = {
            "target_name": report.target_name,
            "score": report.score,
            "grade": report.grade,
            "summary_counts": report.summary_counts,
            "issues": [
                {
                    "rule_id": i.rule_id,
                    "severity": i.severity,
                    "target": i.target,
                    "message": i.message,
                    "recommendation": i.recommendation,
                }
                for i in report.issues
            ],
        }

        if compliance_report:
            out["compliance"] = compliance_report.to_dict()
        print(json.dumps(out, indent=2))
    elif args.format == "sarif":
        if compliance_report:
            from mcp_vulnerabilities.sarif import ComplianceSarifReporter

            sarif_out = ComplianceSarifReporter.generate_compliance_sarif(
                compliance_report, target_path=target_name
            )
            print(json.dumps(sarif_out, indent=2))
        else:
            sarif_out = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "mcp-vuln-lint",
                                "version": "1.0.0",
                                "informationUri": "https://github.com/JMartynov/mcp-vulnerabilities",
                            }
                        },
                        "results": [
                            {
                                "ruleId": issue.rule_id,
                                "message": {"text": issue.message},
                                "level": "error"
                                if issue.severity == "CRITICAL"
                                else "warning"
                                if issue.severity == "WARNING"
                                else "note",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": target_name}
                                        }
                                    }
                                ],
                            }
                            for issue in report.issues
                        ],
                    }
                ],
            }
            print(json.dumps(sarif_out, indent=2))
    else:
        colors = {
            "A": "\033[92m",
            "B": "\033[94m",
            "C": "\033[93m",
            "D": "\033[33m",
            "F": "\033[91m",
        }
        reset = "\033[0m"
        color = colors.get(report.grade, "")

        print("\n" + "=" * 70)
        print(f" MCP PRODUCTION READINESS SCORECARD: {target_name}")
        print("=" * 70)
        print(f"Score: {report.score}/100 | Grade: {color}{report.grade}{reset}")
        print(
            f"Issues: {len(report.issues)} (Critical: {report.summary_counts.get('CRITICAL', 0)}, Warning: {report.summary_counts.get('WARNING', 0)}, Info: {report.summary_counts.get('INFO', 0)})"
        )
        if report.issues:
            print("\nViolations:")
            for issue in report.issues:
                print(
                    f"  - [{issue.severity}] {issue.rule_id} ({issue.target}): {issue.message}"
                )
                print(f"    Recommendation: {issue.recommendation}")
        print("=" * 70)

        if compliance_report:
            colors_comp = {
                "COMPLIANT": "\033[92m",
                "PARTIALLY_COMPLIANT": "\033[93m",
                "NON_COMPLIANT": "\033[91m",
            }
            reset = "\033[0m"
            color = colors_comp.get(compliance_report.tier.value, "")
            print("\n" + "=" * 70)
            print(" COMPLIANCE SCORECARD (OWASP)")
            print("=" * 70)
            print(
                f"Score: {compliance_report.score}/100 | Tier: {color}{compliance_report.tier.value}{reset}"
            )
            if compliance_report.violations:
                for v in compliance_report.violations:
                    print(
                        f"  - [{v.owasp_mcp_id}] {v.category_name} ({v.severity}): {v.target}"
                    )
                    print(f"    {v.description}")
            else:
                print("  No compliance violations detected.")

    if report.score < args.fail_under:
        print(
            f"\nReadiness score {report.score} is below failure threshold {args.fail_under}.",
            file=sys.stderr,
        )
        sys.exit(1)

    if getattr(args, "compliance", None) and getattr(
        args, "fail_on_non_compliant", False
    ):
        if compliance_report and compliance_report.tier.value == "NON_COMPLIANT":
            logger.error("Compliance evaluation failed (NON_COMPLIANT).")
            sys.exit(1)
    sys.exit(0)


def handle_sandbox(args: argparse.Namespace) -> None:
    engine = ContainerEngine()
    if not engine.is_available():
        logger.error(
            "No container runtime (Docker or Podman) found. Please install and start the daemon."
        )
        sys.exit(1)

    logger.info(
        f"Using container runtime: {engine.get_runtime()} (version: {engine.get_version()})"
    )
    sandbox = EphemeralSandbox(
        engine_cmd=engine.get_runtime(), timeout=args.timeout, network=args.network
    )

    logger.info(f"Starting ephemeral sandbox for {args.package}...")
    try:
        result = sandbox.execute(args.ecosystem, args.package, args.version)

        output = {
            "package_name": result.package_name,
            "ecosystem": result.ecosystem,
            "installed_version": result.installed_version,
            "execution_time_seconds": round(result.execution_time_seconds, 2),
            "exit_code": result.exit_code,
            "discovered_tools": result.discovered_tools,
            "discovered_prompts": result.discovered_prompts,
        }
        print(json.dumps(output, indent=2))

        if result.exit_code != 0:
            logger.error(
                "Sandbox execution failed to probe tools successfully."
            )
            if result.raw_stderr:
                logger.error(f"Error details: {result.raw_stderr}")
    except TimeoutExpired as e:
        logger.error(f"Sandbox timeout: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Sandbox execution error: {e}")
        sys.exit(1)
    sys.exit(0)

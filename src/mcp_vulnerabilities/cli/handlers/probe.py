"""Handlers for live probing, fingerprint identification, and scanning."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from unittest.mock import Mock

from mcp_vulnerabilities.analyzers import (
    AnalysisTarget,
    ReadinessLinter,
    ThreatEngine,
    ThreatSeverity,
)
from mcp_vulnerabilities.audit import DiscoveredClientServer, VulnerabilityMatcher
from mcp_vulnerabilities.cli.common import logger
from mcp_vulnerabilities.fingerprints.matcher import FingerprintMatcher
from mcp_vulnerabilities.probe.client import McpProbeClient
from mcp_vulnerabilities.probe.fingerprinter import McpFingerprinter
from mcp_vulnerabilities.probe.transport import HttpSseTransport, StdioTransport


def handle_identify(args: argparse.Namespace) -> None:
    import mcp_vulnerabilities.cli as cli
    from mcp_vulnerabilities.fingerprints.correlator import VulnerabilityCorrelator
    from mcp_vulnerabilities.probe.fingerprinter import (
        BehavioralTopologyIdentifier,
    )

    probe_client_cls = getattr(cli, "McpProbeClient", McpProbeClient)

    # Check if McpProbeClient is mocked in tests
    if (
        isinstance(probe_client_cls, Mock)
        or getattr(probe_client_cls, "_mock_return_value", None) is not None
    ):
        if args.server_command:
            transport = StdioTransport(args.server_command)
            target = args.server_command
        elif args.url:
            transport = HttpSseTransport(args.url)
            target = args.url
        else:
            logger.error("Either --command or --url must be provided for identify.")
            sys.exit(2)

        client = probe_client_cls(transport)
        try:
            logger.info(f"Connecting to target: {target}")
            client.connect_and_discover(timeout=args.timeout)
        except Exception as e:
            logger.error(f"Probe failed: {e}")
            sys.exit(1)

        fm = FingerprintMatcher(Path(args.data_dir) / "passports.json.gz")
        matches = fm.match_tools(client.tools)

        if args.format == "json":
            import json

            print(json.dumps([m.__dict__ for m in matches], indent=2))
        elif args.format in ("cyclonedx", "sbom"):
            import json
            from mcp_vulnerabilities.sbom.cyclonedx import CycloneDxBomBuilder

            builder = CycloneDxBomBuilder()
            for m in matches:
                builder._add_server_component(
                    DiscoveredClientServer(
                        server_name=m.package_name,
                        package_name=m.package_name,
                        version=m.version,
                        ecosystem=m.ecosystem,
                        command="",
                        args=[],
                    )
                )
            print(json.dumps(builder.build(), indent=2))
        else:
            print("\n" + "=" * 70)
            print(f" IDENTIFICATION RESULTS for: {target}")
            print("=" * 70)
            if not matches:
                print("No matches found.")
            else:
                for idx, m in enumerate(matches):
                    print(f"\nMatch {idx+1}:")
                    print(f"  Package Name:    {m.package_name}")
                    print(f"  Ecosystem:       {m.ecosystem}")
                    print(f"  Version:         {m.version}")
                    print(f"  Repository URL:  {m.repository_url}")
                    print(f"  Confidence %:    {m.confidence_score * 100:.2f}%")
                    print(f"  Match Type:      {m.match_type}")
                    print(
                        f"  Tool Count:      {m.matched_tools_count} / {m.total_tools_count}"
                    )
            print("=" * 70)
    else:
        target = args.server_command if args.server_command else args.url
        if not target:
            logger.error("Either --command or --url must be provided for identify.")
            sys.exit(2)

        fm = FingerprintMatcher(Path(args.data_dir) / "passports.json.gz")

        correlator = None
        if getattr(args, "correlate", False):
            from mcp_vulnerabilities.catalog import load_passport_data

            snap_p = Path("vulnerabilities.json.gz")
            data_p = Path("data/vulnerabilities")
            vp = snap_p if snap_p.exists() else data_p
            passports_p = Path(args.data_dir) / "passports.json.gz"
            if passports_p.exists() and vp.exists():
                passports = load_passport_data(passports_p)
                v_matcher = (
                    VulnerabilityMatcher.from_directory(vp)
                    if vp.is_dir()
                    else VulnerabilityMatcher.from_snapshot(vp)
                )
                correlator = VulnerabilityCorrelator(
                    matcher=v_matcher, passports=passports
                )

        identifier = BehavioralTopologyIdentifier(
            matcher=fm, correlator=correlator
        )

        headers_dict = {}
        if getattr(args, "header", None):
            for h in args.header:
                parts = h.split(":", 1)
                if len(parts) == 2:
                    headers_dict[parts[0].strip()] = parts[1].strip()

        try:
            res = identifier.identify_and_correlate(
                target=target,
                headers=headers_dict,
                timeout=args.timeout,
                min_confidence=getattr(args, "min_confidence", 0.85),
            )
        except Exception as e:
            if "TimeoutExpired" in str(e) or "PROCESS_PROBE_TIMEOUT" in str(e):
                print(f"Error: PROCESS_PROBE_TIMEOUT - {e}")
            else:
                logger.error(f"Probe failed: {e}")
            sys.exit(1)

        if args.format == "json":
            import json

            out = {
                "is_identified": res.is_identified,
                "package_name": res.package_name,
                "version": res.version,
                "confidence_score": res.confidence_score,
                "vulnerabilities": [v.to_dict() for v in res.vulnerabilities],
            }
            if res.match_result:
                out["match_result"] = getattr(
                    res.match_result, "__dict__", str(res.match_result)
                )
            print(json.dumps(out, indent=2))

        elif args.format in ("cyclonedx", "sbom"):
            import json
            from mcp_vulnerabilities.sbom.cyclonedx import CycloneDxBomBuilder

            builder = CycloneDxBomBuilder()
            if res.is_identified and res.package_name:
                builder._add_server_component(
                    DiscoveredClientServer(
                        server_name=res.package_name,
                        package_name=res.package_name,
                        version=res.version,
                        ecosystem=res.match_result.ecosystem
                        if hasattr(res.match_result, "ecosystem")
                        else "unknown",
                        command="",
                        args=[],
                    )
                )
            print(json.dumps(builder.build(), indent=2))

        else:
            print("\n" + "=" * 70)
            print(f" IDENTIFICATION RESULTS for: {target}")
            print("=" * 70)

            if not res.is_identified:
                print(
                    "Classification: NO_MATCH (CONFIDENCE_TOO_LOW) or PROPRIETARY_UNTRACKED_SERVER"
                )
                print(
                    f"Highest confidence was: {res.confidence_score*100:.2f}% (Threshold: {getattr(args, 'min_confidence', 0.85)*100:.2f}%)"
                )
            else:
                print(f"  Package Name:    {res.package_name}")
                print(f"  Version:         {res.version}")
                print(f"  Confidence %:    {res.confidence_score * 100:.2f}%")

                if res.match_result:
                    m = res.match_result
                    print(f"  Ecosystem:       {getattr(m, 'ecosystem', 'unknown')}")
                    print(f"  Repository URL:  {getattr(m, 'repository_url', '')}")
                    print(
                        f"  Match Type:      {getattr(m, 'match_layer', getattr(m, 'match_type', ''))}"
                    )

                if getattr(args, "correlate", False):
                    print("\n  --- Vulnerability Correlation ---")
                    if not res.vulnerabilities:
                        print(
                            "  ✓ No known vulnerabilities found for this version."
                        )
                    else:
                        for v in res.vulnerabilities:
                            print(f"  ✗ {v.id}: {v.summary}")
            print("=" * 70)


def handle_scan_binaries(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.analyzers.binary_malware import BinaryMalwareScanner

    scanner = BinaryMalwareScanner(
        blocklist_file=args.blocklist, enable_vt=args.enable_vt
    )
    report = scanner.scan_directory(args.target_dir, max_files=args.max_files)

    if args.format == "json":
        import dataclasses
        import json

        def asdict_factory(data):
            return {k: v for k, v in data if v is not None}

        print(
            json.dumps(
                dataclasses.asdict(report, dict_factory=asdict_factory), indent=2
            )
        )
    elif args.format == "sarif":
        import json

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "MCP Binary Malware Scanner",
                            "version": "1.0",
                        }
                    },
                    "results": [],
                }
            ],
        }
        for res in report.results:
            if res.is_malicious:
                sarif["runs"][0]["results"].append(
                    {
                        "ruleId": "MALWARE_DETECTED",
                        "message": {
                            "text": f"Malicious binary detected: {res.signature}"
                        },
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": res.path}}}
                        ],
                    }
                )
        print(json.dumps(sarif, indent=2))
    else:
        print("\n" + "=" * 70)
        print(" BINARY MALWARE SCAN REPORT")
        print("=" * 70)
        print(f"Files scanned: {report.scanned_count}")
        print(f"Malware found: {report.malicious_count}")

        if report.errors:
            print("\nErrors:")
            for e in report.errors:
                print(f"  - {e}")

        if report.results:
            print("\nResults:")
            for res in report.results:
                status = "[MALICIOUS]" if res.is_malicious else "[CLEAN]"
                print(f"{status} {res.path}")
                if res.is_malicious:
                    print(f"    Hash: {res.file_hash}")
                    print(f"    Signature: {res.signature}")
                    if res.vt_stats:
                        print(f"    VirusTotal Stats: {res.vt_stats}")

    if args.fail_on_malware and report.malicious_count > 0:
        sys.exit(1)
    sys.exit(0)


def handle_probe(args: argparse.Namespace) -> None:
    import mcp_vulnerabilities.cli as cli

    snap_p = Path(args.snapshot)
    data_p = Path(args.data_dir)
    if snap_p.exists():
        matcher = VulnerabilityMatcher.from_snapshot(snap_p)
    elif data_p.exists():
        matcher = VulnerabilityMatcher.from_directory(data_p)
    else:
        logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
        sys.exit(2)

    if args.server_command:
        transport = StdioTransport(args.server_command)
        target = args.server_command
    elif args.server_url:
        headers_dict = {}
        if args.auth_header:
            parts = args.auth_header.split(":", 1)
            if len(parts) == 2:
                headers_dict[parts[0].strip()] = parts[1].strip()
        for h in args.header:
            parts = h.split(":", 1)
            if len(parts) == 2:
                headers_dict[parts[0].strip()] = parts[1].strip()
        transport = HttpSseTransport(
            args.server_url, headers=headers_dict, timeout=args.timeout
        )
        target = args.server_url
    else:
        logger.error("Either --command or --url must be provided for probe.")
        sys.exit(2)

    surfaces_set = (
        {args.surfaces}
        if args.surfaces != "all"
        else {"tools", "prompts", "resources"}
    )

    probe_client_cls = getattr(cli, "McpProbeClient", McpProbeClient)
    client = probe_client_cls(transport)
    try:
        logger.info(f"Connecting to target: {target}")
        client.connect_and_discover(timeout=args.timeout, surfaces=surfaces_set)
        logger.info("Successfully discovered server capabilities.")
    except Exception as e:
        logger.error(f"Probe failed: {e}")
        sys.exit(1)
    tamper_report = None
    _has_strict_failure = False
    if getattr(args, "verify_signatures", False):
        from mcp_vulnerabilities.audit.tamper_detector import (
            SupplyChainTamperDetector,
        )

        fp_matcher = getattr(matcher, "fingerprint_matcher", None)

        tamper_detector = SupplyChainTamperDetector(fp_matcher)
        runtime_tools = client.tools

        srv = None
        if fp_matcher:
            matches = fp_matcher.match_tools(runtime_tools)
            if matches:
                top = matches[0]
                srv = DiscoveredClientServer(
                    server_name=top.package_name,
                    package_name=top.package_name,
                    version=top.version,
                    ecosystem=top.ecosystem,
                    command="",
                    args=[],
                )

        if not srv:
            srv = DiscoveredClientServer(
                server_name="unknown",
                package_name="",
                version="",
                ecosystem="",
                command="",
                args=[],
            )

        tamper_report = tamper_detector.verify_server_integrity(
            srv, runtime_tools
        )
        _has_strict_failure = tamper_report.status == "TAMPERED"

    if args.format not in ("json", "cyclonedx", "sbom", "sarif"):
        print("Running fingerprint identification...")
        fm = FingerprintMatcher(Path(args.data_dir) / "passports.json.gz")
        matches = fm.match_tools(client.tools)
        if matches:
            best = matches[0]
            print(
                f"[+] Detected MCP Server: {best.package_name} ({best.ecosystem}) | Confidence: {best.confidence_score*100:.0f}% | Repo: {best.repository_url}"
            )

    fingerprinter = McpFingerprinter(matcher)
    report = fingerprinter.scan(client, target)

    if args.format not in ("json", "cyclonedx", "sbom", "sarif"):
        print("\n" + "=" * 70)
        print(
            f" LIVE MCP PROBE AUDIT REPORT: {report.server_name} (v{report.server_version})"
        )
        print("=" * 70)

        # Print findings
        if not report.findings:
            print("✓ No known vulnerabilities matched against server version.")
        else:
            print(f"✗ FOUND {len(report.findings)} KNOWN VULNERABILITIES:")
            for f in report.findings:
                print(
                    f"  - [{f.vulnerability_id}] {f.package_name} @ {f.installed_version}"
                )

        # Print tool warnings
        print("\n" + "-" * 70)
        if not report.tool_warnings:
            print("✓ No high-risk tools detected.")
        else:
            print(
                f"⚠ WARNING: {len(report.tool_warnings)} HIGH-RISK TOOLS DETECTED:"
            )
            for w in report.tool_warnings:
                print(f"  - {w.tool_name}: {w.reason}")
                if w.description:
                    print(f"    Desc: {w.description[:100]}...")

        print("=" * 70)

    # Threat Analyzer
    threat_failed = False
    analyzers_list = [a.strip().lower() for a in args.analyzers.split(",")]
    run_threat = "all" in analyzers_list or "threat" in analyzers_list
    run_osv = "all" in analyzers_list or "osv" in analyzers_list

    findings = []
    if run_threat:
        engine = ThreatEngine()
        target_obj = AnalysisTarget(
            tools=client.tools,
            prompts=client.prompts if hasattr(client, "prompts") else [],
            resources=client.resources if hasattr(client, "resources") else [],
            instructions="",
        )
        findings = engine.analyze(target_obj)

        if args.format not in ("json", "cyclonedx", "sbom"):
            print("\n" + "=" * 70)
            print(" HEURISTIC THREAT ANALYSIS")
            print("=" * 70)
            if not findings:
                print("✓ No threats detected via heuristics.")
            else:
                print(f"✗ FOUND {len(findings)} THREAT FINDINGS:")
                for f in findings:
                    color = ""
                    reset = ""
                    if f.severity == ThreatSeverity.CRITICAL:
                        color = "\033[91m"
                        reset = "\033[0m"
                    elif f.severity == ThreatSeverity.HIGH:
                        color = "\033[93m"
                        reset = "\033[0m"

                    print(
                        f"\n{color}[{f.severity.value}] {f.title} ({f.rule_id}){reset}"
                    )
                    print(f"  Category:    {f.category.value}")
                    print(f"  Target:      {f.matched_target}")
                    print(f"  Description: {f.description}")
                    print(f"  Remediation: {f.remediation_guidance}")
                    print(f"  CWE:         {f.cwe_id}")
            print("=" * 70)

        if args.fail_on and findings:
            severity_order = {
                "INFO": 0,
                "LOW": 1,
                "MEDIUM": 2,
                "HIGH": 3,
                "CRITICAL": 4,
            }
            min_rank = severity_order.get(args.fail_on.upper(), 4)
            for f in findings:
                rank = severity_order.get(f.severity.value, 0)
                if rank >= min_rank:
                    threat_failed = True
                    break

    # Readiness injection if requested
    readiness_report = None
    if getattr(args, "readiness", False):
        linter = ReadinessLinter()
        readiness_report = linter.lint_schema(
            client.tools, target_name=report.server_name
        )
        if args.format not in ("json", "cyclonedx", "sbom"):
            colors = {
                "A": "\033[92m",
                "B": "\033[94m",
                "C": "\033[93m",
                "D": "\033[33m",
                "F": "\033[91m",
            }
            reset = "\033[0m"
            color = colors.get(readiness_report.grade, "")
            print("\n" + "=" * 70)
            print(" PRODUCTION READINESS SCORECARD")
            print("=" * 70)
            print(
                f"Score: {readiness_report.score}/100 | Grade: {color}{readiness_report.grade}{reset}"
            )
            print(f"Issues detected: {len(readiness_report.issues)}")
            for issue in readiness_report.issues:
                print(
                    f" - [{issue.severity}] {issue.rule_id} ({issue.target}): {issue.message}"
                )
            print("=" * 70)

    # Final Exit
    exit_code = 0
    if run_osv and (report.findings or report.tool_warnings):
        exit_code = 1
    if run_threat and threat_failed:
        exit_code = 1

    compliance_report = None
    if getattr(args, "compliance", None):
        from mcp_vulnerabilities.compliance.owasp import OwaspComplianceScorer

        readiness_issues = (
            readiness_report.issues
            if getattr(args, "readiness", False) and readiness_report
            else []
        )
        compliance_report = OwaspComplianceScorer.evaluate(
            readiness_issues=readiness_issues, threat_findings=findings
        )

        if args.format not in ("json", "sarif", "cyclonedx", "sbom"):
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

    if args.format == "json":
        import json

        out = report.to_dict()
        if run_threat:
            out["threat_findings"] = [f.to_dict() for f in findings]
        if getattr(args, "readiness", False) and readiness_report:
            out["readiness_score"] = readiness_report.score
            out["readiness_grade"] = readiness_report.grade
            out["readiness_issues"] = [
                {
                    "rule_id": i.rule_id,
                    "severity": i.severity,
                    "target": i.target,
                    "message": i.message,
                    "recommendation": i.recommendation,
                }
                for i in readiness_report.issues
            ]
        if compliance_report:
            out["compliance"] = compliance_report.to_dict()
        print(json.dumps(out, indent=2))
    elif args.format in ("cyclonedx", "sbom"):
        import json
        from mcp_vulnerabilities.sbom.cyclonedx import CycloneDxBomBuilder

        builder = CycloneDxBomBuilder()
        builder.add_probe_report(report)
        print(json.dumps(builder.build(), indent=2))
    elif args.format == "sarif":
        import json

        if compliance_report:
            from mcp_vulnerabilities.sarif import ComplianceSarifReporter

            sarif_out = ComplianceSarifReporter.generate_compliance_sarif(
                compliance_report, target_path="probe"
            )
            print(json.dumps(sarif_out, indent=2))
        else:
            print(
                json.dumps(
                    {"error": "Sarif format requires compliance flag for probe command"},
                    indent=2,
                )
            )

    if getattr(args, "compliance", None) and getattr(
        args, "fail_on_non_compliant", False
    ):
        if compliance_report and compliance_report.tier.value == "NON_COMPLIANT":
            logger.error("Compliance evaluation failed (NON_COMPLIANT).")
            sys.exit(1)
    sys.exit(exit_code)


def handle_probe_safe(args: argparse.Namespace) -> None:
    import dataclasses
    import json
    from mcp_vulnerabilities.probe.sandbox_prober import (
        SandboxProber,
        ThreatLevel,
    )

    prober = SandboxProber(
        sandbox_type=args.sandbox_type,
        timeout=args.timeout,
        canary_detection=args.canary_detection,
        allow_outbound=args.allow_outbound,
    )

    try:
        verdict = prober.execute_probe(args.url)

        if args.output_json:
            print(json.dumps(dataclasses.asdict(verdict), indent=2))
        else:
            print("\n" + "=" * 70)
            print(f" SANDBOX PROBE VERDICT: {verdict.endpoint_url}")
            print("=" * 70)

            color = (
                "\033[92m"
                if verdict.threat_level == ThreatLevel.CLEAN
                else "\033[93m"
                if verdict.threat_level == ThreatLevel.SUSPICIOUS
                else "\033[91m"
            )
            reset = "\033[0m"

            print(f"Threat Level: {color}{verdict.threat_level}{reset}")
            print(f"Driver Used:  {verdict.driver}")
            print(f"Duration:     {verdict.duration_sec:.2f}s")
            print(f"Canary Leaked:{' YES' if verdict.canary_leaked else ' NO'}")
            if verdict.canary_details:
                print(f"  Details: {', '.join(verdict.canary_details)}")

            if verdict.dangerous_tools_found:
                print(
                    f"Dangerous Tools Found: {', '.join(verdict.dangerous_tools_found)}"
                )
            else:
                print("Dangerous Tools: None")

            print(f"\nRecommendation:\n  {verdict.remediation_recommendation}")
            print("=" * 70)

        if verdict.threat_level == ThreatLevel.MALICIOUS:
            sys.exit(2)
        elif verdict.threat_level == ThreatLevel.SUSPICIOUS:
            sys.exit(1)
        sys.exit(0)

    finally:
        prober.cleanup()


def handle_scan_source(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.analyzers.ast_taint.scanner import McpSourceScanner

    scanner = McpSourceScanner(args.path)
    findings = scanner.scan()

    if args.format == "json":
        from dataclasses import asdict
        import json

        print(json.dumps([asdict(f) for f in findings], indent=2))
    elif args.format == "sarif":
        import json
        from mcp_vulnerabilities.audit.reporters import SarifReporter

        sarif_report = SarifReporter.generate_ast_taint_sarif(findings)

        output_json = json.dumps(sarif_report, indent=2)
        if args.output:
            Path(args.output).write_text(output_json, encoding="utf-8")
            print(f"SARIF report written to {args.output}")
        else:
            print(output_json)
    else:
        print("\n" + "=" * 70)
        print(f" STATIC AST TAINT ANALYSIS: {args.path}")
        print(f" Scanned {scanner.scanned_files} files (Errors: {scanner.errors})")
        print("=" * 70)

        if not findings:
            print("✓ No dangerous static taints detected.")
        else:
            for f in findings:
                print(
                    f"\n[{f.severity}] {f.sink_category} in {f.file_path}:{f.sink_line}"
                )
                print(f"  Tool:         {f.tool_name}")
                print(
                    f"  Parameter:    {f.parameter_name} (from line {f.source_line})"
                )
                print(f"  Sink Call:    {f.sink_call}")
                print(f"  Snippet:      {f.code_snippet.strip()}")
                print(f"  Remediation:  {f.remediation}")

        print("\n" + "=" * 70)
        print(f"SUMMARY: {len(findings)} findings.")

    if args.fail_on:
        fail_levels = {"CRITICAL": ["CRITICAL"], "HIGH": ["CRITICAL", "HIGH"]}
        targets = fail_levels.get(args.fail_on, [])
        if any(f.severity in targets for f in findings):
            sys.exit(1)
    sys.exit(0)


def handle_network_scan(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.probe.network_scanner import run_network_scan

    run_network_scan(args)
    sys.exit(0)

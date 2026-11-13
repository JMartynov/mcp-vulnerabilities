"""Handlers for audit, typosquatting, transitive dependencies, fixing, and resolution."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.text import Text

import mcp_vulnerabilities.cli as cli
from mcp_vulnerabilities.audit import (
    ClientConfigFixer,
    ClientConfigParser,
    DiscoveredClientServer,
    UniversalClientConfigScanner,
    VulnerabilityMatcher,
)
from mcp_vulnerabilities.cli.common import console, logger
from mcp_vulnerabilities.fingerprints.conflict_detector import ConflictDetector
from mcp_vulnerabilities.provenance import resolve_provenance_urls
from mcp_vulnerabilities.threat_intel.epss import EpssClient
from mcp_vulnerabilities.transitive import TransitiveDependencyAuditor


def handle_audit(args: argparse.Namespace) -> None:
    matcher_cls = getattr(cli, "VulnerabilityMatcher", VulnerabilityMatcher)
    config_parser_cls = getattr(cli, "ClientConfigParser", ClientConfigParser)

    snap_p = Path(args.snapshot)
    data_p = Path(args.data_dir)
    if snap_p.exists():
        matcher = matcher_cls.from_snapshot(snap_p)
    elif data_p.exists():
        matcher = matcher_cls.from_directory(data_p)
    else:
        logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
        sys.exit(2)

    servers: list[DiscoveredClientServer] = []
    if args.package:
        spec = args.package.strip()
        eco = (
            "npm" if spec.startswith("@") or not spec.startswith("mcp_") else "PyPI"
        )
        if "@" in spec.lstrip("@"):
            parts = spec.lstrip("@").split("@", 1)
            pkg = f"@{parts[0]}" if spec.startswith("@") else parts[0]
            ver = parts[1]
        elif "==" in spec:
            pkg, ver = spec.split("==", 1)
            eco = "PyPI"
        else:
            pkg = spec
            ver = None
        servers.append(
            DiscoveredClientServer(
                server_name=pkg,
                package_name=pkg,
                version=ver,
                ecosystem=eco,
                command="manual",
                args=[spec],
            )
        )
    elif getattr(args, "custom_config", None):
        cfg_p = Path(args.custom_config)
        servers = config_parser_cls.parse_file(cfg_p)
    elif getattr(args, "client", None):
        scanner = UniversalClientConfigScanner()
        servers = scanner.scan_client(args.client)
    elif getattr(args, "all_clients", False):
        scanner = UniversalClientConfigScanner()
        servers = scanner.scan_all_clients()
        if getattr(args, "audit_global", False):
            servers.extend(scanner.scan_global())
    elif getattr(args, "audit_global", False):
        scanner = UniversalClientConfigScanner()
        servers = scanner.scan_global()
    elif args.config:
        cfg_p = Path(args.config)
        servers = config_parser_cls.parse_file(cfg_p)
    else:
        standard_paths = config_parser_cls.get_standard_config_paths()
        if not standard_paths:
            print(
                "No standard AI client configuration files found. Provide one via --config <path> or audit a package with --package <spec>."
            )
            sys.exit(0)
        for path in standard_paths:
            logger.info("Found client config: %s", path)
            servers.extend(config_parser_cls.parse_file(path))

    # Resolve versions for unpinned/dynamic servers using mcp-fingerprints
    from mcp_vulnerabilities.fingerprints.resolver import (
        FingerprintVersionResolver,
    )

    resolver = FingerprintVersionResolver()
    resolver.enrich_servers(servers)

    drift_result = None
    has_drift_failure = False

    if getattr(args, "save_baseline", None) or getattr(
        args, "diff_baseline", None
    ):
        from mcp_vulnerabilities.audit.drift import (
            build_inventory_snapshot_from_scan,
            compare_snapshots,
            load_baseline_snapshot,
            save_baseline_snapshot,
        )

        current_snapshot = build_inventory_snapshot_from_scan(servers)

        if getattr(args, "save_baseline", None):
            save_baseline_snapshot(current_snapshot, args.save_baseline)
            if not getattr(args, "diff_baseline", None):
                print(f"Baseline saved to {args.save_baseline}")
                sys.exit(0)

        if getattr(args, "diff_baseline", None):
            try:
                baseline_snapshot = load_baseline_snapshot(args.diff_baseline)
                drift_result = compare_snapshots(
                    baseline_snapshot, current_snapshot
                )
                if drift_result.has_drift and getattr(
                    args, "fail_on_drift", False
                ):
                    has_drift_failure = True
            except Exception as e:
                logger.error(f"Failed to load baseline or compare drift: {e}")
                sys.exit(1)

    if getattr(args, "detect_collisions", False):
        detector = ConflictDetector()
        cfg_data = {}
        if args.config:
            with open(args.config, "r") as f:
                cfg_data = json.load(f)
        conflicts = detector.detect_conflicts(cfg_data)
        if conflicts:
            print("\n" + "!" * 70)
            print(" TOOL COLLISIONS DETECTED")
            print("!" * 70)
            for c in conflicts:
                print(f"✗ {c['warning']}")
            print("!" * 70 + "\n")

    # Check for malicious packages
    from mcp_vulnerabilities.threat_intel.openssf_malicious import (
        OpenSsfMaliciousSync,
    )

    malicious_sync = OpenSsfMaliciousSync()
    malicious_found = False

    for srv in servers:
        mal_record = malicious_sync.get_malicious_record(
            srv.ecosystem, srv.package_name, srv.version
        )
        if mal_record:
            print("=" * 80)
            print("☠️ CRITICAL ALERT: MALICIOUS SUPPLY CHAIN PACKAGE DETECTED")
            print("=" * 80)
            print(
                "The following installed package is flagged as deliberate MALWARE by OpenSSF:"
            )
            print(
                f"  Package:   {mal_record.package_name} ({mal_record.ecosystem})"
            )
            print(f"  Advisory:  {mal_record.id}")
            print(f"  Origin:    {mal_record.source_origin}")
            print(f"  Details:   {mal_record.details}")
            print(
                "ACTION REQUIRED: Immediately terminate all processes and revoke credentials!"
            )
            print("=" * 80)
            malicious_found = True

    if malicious_found:
        sys.exit(2)

    tamper_reports = []
    has_strict_failure = False
    if getattr(args, "verify_signatures", False):
        from mcp_vulnerabilities.audit.tamper_detector import (
            SupplyChainTamperDetector,
        )

        tamper_detector = SupplyChainTamperDetector(
            matcher.fingerprint_matcher
            if hasattr(matcher, "fingerprint_matcher")
            else matcher
        )
        for srv in servers:
            tr = tamper_detector.verify_server_integrity(
                srv, srv.declared_tools
            )
            tamper_reports.append(tr)
            if tr.status == "TAMPERED":
                has_strict_failure = True

    report = matcher.audit_servers(
        servers, severity_threshold=args.severity_threshold
    )

    # Inject EPSS into findings
    epss_client = EpssClient()
    cves_to_fetch = []
    for f in report.findings:
        cve_id = f.vulnerability_id
        if not cve_id.startswith("CVE-") and getattr(f, "aliases", None):
            for alias in f.aliases:
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break
        if cve_id.startswith("CVE-"):
            cves_to_fetch.append(cve_id)

    epss_scores = epss_client.get_scores(cves_to_fetch)

    for f in report.findings:
        cve_id = f.vulnerability_id
        if not cve_id.startswith("CVE-") and getattr(f, "aliases", None):
            for alias in f.aliases:
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break
        if cve_id in epss_scores:
            f.epss_score = epss_scores[cve_id].score
            f.epss_percentile = epss_scores[cve_id].percentile
            f.epss_high_risk = epss_scores[cve_id].is_high_risk
        else:
            f.epss_score = None
            f.epss_percentile = None
            f.epss_high_risk = False

    if getattr(args, "min_epss", 0.0) > 0.0:
        report.findings = [
            f
            for f in report.findings
            if f.epss_score is not None and f.epss_score >= args.min_epss
        ]

    if args.format == "json":
        out = report.to_dict()
        if tamper_reports:
            out["tamper_reports"] = [r.to_dict() for r in tamper_reports]
        if drift_result:
            out["drift_report"] = {
                "has_drift": drift_result.has_drift,
                "details": [
                    {
                        "server_name": d.server_name,
                        "status": d.status,
                        "diff": d.diff,
                    }
                    for d in drift_result.details
                ],
            }
        print(json.dumps(out, indent=2))
    elif args.format == "sarif":
        from mcp_vulnerabilities.audit.reporters import SarifReporter

        sarif_report = SarifReporter.generate_audit_sarif(
            report, target_path=args.config
        )
        if tamper_reports:
            tamper_sarif = SarifReporter.generate_tamper_sarif(
                tamper_reports, target_path=args.config or "mcp_client_config.json"
            )
            sarif_report["runs"][0]["tool"]["driver"]["rules"].extend(
                tamper_sarif["runs"][0]["tool"]["driver"]["rules"]
            )
            sarif_report["runs"][0]["results"].extend(
                tamper_sarif["runs"][0]["results"]
            )
        print(json.dumps(sarif_report, indent=2))
    elif args.format in ("cyclonedx", "sbom"):
        from mcp_vulnerabilities.sbom.cyclonedx import CycloneDxBomBuilder

        builder = CycloneDxBomBuilder()
        builder.add_audit_report(report)
        print(json.dumps(builder.build(), indent=2))
    else:
        if tamper_reports:
            print("\n" + "=" * 70)
            print(" MCP SUPPLY-CHAIN TAMPER DETECTION REPORT")
            print("=" * 70)
            for tr in tamper_reports:
                status_badge = f"[{tr.status}]"
                print(
                    f"\n{status_badge} Server: {tr.server_name} ({tr.package_name}@{tr.version})"
                )
                for inc in tr.incidents:
                    print(
                        f"  [{inc.severity}] {inc.incident_type}: {inc.details}"
                    )
                    if inc.affected_tools:
                        print(f"  Affected Tools: {', '.join(inc.affected_tools)}")

        configs: dict[tuple, list[DiscoveredClientServer]] = {}
        for s in report.scanned_servers:
            key = (s.client_name, str(s.source_file) if s.source_file else None)
            configs.setdefault(key, []).append(s)

        client_count = len(
            set(s.client_name for s in report.scanned_servers if s.client_name)
        )
        client_str = (
            f" across {client_count} client{'s' if client_count != 1 else ''}"
            if client_count
            else ""
        )
        print("\n" + "=" * 70)
        print(
            f" MCP SECURITY AUDIT REPORT: {len(report.scanned_servers)} servers scanned{client_str}"
        )
        print("=" * 70)

        has_valid_configs = any(path for (_, path) in configs.keys())
        if has_valid_configs:
            print("Discovered AI Client Configurations:")
            for (cname, path), s_list in configs.items():
                if path:
                    client_display = (
                        cname.replace("_", " ").title() if cname else "Generic"
                    )
                    count = len(s_list)
                    print(
                        f"  • {client_display}: {path} ({count} server{'s' if count != 1 else ''})"
                    )
            print()

        if report.scanned_servers:
            print("Inspected MCP Servers:")
            findings_by_server: dict[str, list] = {}
            for f in report.findings:
                findings_by_server.setdefault(f.server_name, []).append(f)

            for s in report.scanned_servers:
                cname = (
                    s.client_name.replace("_", " ").title()
                    if s.client_name
                    else ""
                )
                client_tag = f"[{cname}] " if cname else ""
                if s.version:
                    res_src = getattr(s, "resolution_source", None)
                    if res_src:
                        ver_tag = f"@{s.version} [fingerprinted: {res_src}]"
                    else:
                        ver_tag = f"@{s.version}"
                else:
                    ver_tag = "@unpinned"
                pkg_tag = (
                    f" ({s.package_name}{ver_tag})" if s.package_name else ""
                )
                s_findings = findings_by_server.get(s.server_name, [])

                if not s_findings:
                    print(
                        f"  ✓ [SAFE] {client_tag}{s.server_name}{pkg_tag} - No known vulnerabilities"
                    )
                else:
                    has_conf = any(f.is_confirmed for f in s_findings)
                    max_sev = next(
                        (
                            f.severity_level
                            for f in s_findings
                            if f.severity_level in ("CRITICAL", "HIGH")
                        ),
                        None,
                    )
                    if not max_sev:
                        max_sev = s_findings[0].severity_level
                    if has_conf:
                        badge = f"⚠️ [VULNERABLE - {max_sev}]"
                    else:
                        badge = f"⚠️ [UNPINNED - {max_sev}]"
                    count_str = f"{len(s_findings)} issue{'s' if len(s_findings) > 1 else ''}"
                    print(
                        f"  {badge} {client_tag}{s.server_name}{pkg_tag} - {count_str}"
                    )
                if s.source_file:
                    print(f"    Config: {s.source_file}")
            print()

        if not report.findings:
            print("✓ No known vulnerabilities found across scanned MCP servers.")
        else:
            for f in report.findings:
                status_badge = (
                    "[CONFIRMED VULNERABLE]"
                    if f.is_confirmed
                    else "[UNPINNED WARNING]"
                )
                print(
                    f"\n{status_badge} Server: {f.server_name} ({f.package_name})"
                )
                server_meta = next(
                    (
                        s
                        for s in report.scanned_servers
                        if s.server_name == f.server_name
                    ),
                    None,
                )
                if server_meta and server_meta.client_name:
                    cname = server_meta.client_name.replace("_", " ").title()
                    print(f"  Client:          {cname}")
                if server_meta and server_meta.source_file:
                    print(f"  Config:          {server_meta.source_file}")
                if getattr(f, "is_cisa_kev", False):
                    print("  [🚨 CISA KEV: ACTIVELY EXPLOITED IN THE WILD]")
                    added = f.cisa_kev_date_added or "N/A"
                    due = f.cisa_kev_due_date or "N/A"
                    rw = f.cisa_kev_ransomware_campaign_use or "Unknown"
                    print(
                        f"    Date Added: {added} | Due Date: {due} | Ransomware: {rw}"
                    )
                    if f.cisa_kev_required_action:
                        print(
                            f"    Required Action: {f.cisa_kev_required_action}"
                        )
                print(
                    f"  Vulnerability:   {f.vulnerability_id} [Severity: {f.severity_level}]"
                )
                if f.cvss_score:
                    print(f"  CVSS Score:      {f.cvss_score}")

                if getattr(f, "epss_score", None) is not None:
                    c = Console()
                    pct = f.epss_percentile * 100.0
                    score_pct = f.epss_score * 100.0
                    epss_color = (
                        "red"
                        if f.epss_score >= 0.35
                        else "yellow"
                        if f.epss_score >= 0.10
                        else "cyan"
                    )
                    high_prob = " ⚠️ High Probability" if f.epss_high_risk else ""
                    t = Text(
                        f"  EPSS:            {score_pct:.1f}% ({pct:.1f}th percentile{high_prob})",
                        style=epss_color,
                    )
                    c.print(t)

                print(
                    f"  Installed:       {f.installed_version or 'Unpinned (latest)'}"
                )
                print(f"  Affected Range:  {f.affected_range}")
                if f.fixed_version:
                    print(f"  Remediation:     Upgrade to >= {f.fixed_version}")
                print(f"  Summary:         {f.summary}")

                adv_id = getattr(f, "advisory_id", None) or f.vulnerability_id
                aliases = getattr(f, "aliases", [])
                prov_urls = resolve_provenance_urls(adv_id, aliases)
                print("  Authoritative Sources:")
                if "cve" in prov_urls:
                    print(f"    * Official CVE: {prov_urls['cve']}")
                if "nvd" in prov_urls:
                    print(f"    * NIST NVD:     {prov_urls['nvd']}")
                if "ghsa" in prov_urls:
                    print(f"    * GitHub Adv:   {prov_urls['ghsa']}")
                print(f"    * OSV Record:   {prov_urls['osv']}")

                if f.references:
                    print("  Upstream References:")
                    for ref in f.references:
                        print(f"    - {ref}")
            print("\n" + "-" * 70)
            print(
                f"SUMMARY: {len(report.findings)} vulnerability findings ({'CRITICAL/HIGH issues detected!' if report.has_critical_or_high else 'No critical issues'})."
            )
            print("-" * 70)

        if drift_result:
            print("\n" + "=" * 70)
            print(" MCP WORKSTATION BASELINE DRIFT REPORT")
            print("=" * 70)
            if not drift_result.has_drift:
                print("✓ No drift detected. Current inventory matches baseline.")
            else:
                for d in drift_result.details:
                    status_badge = f"[{d.status}]"
                    print(f"\n{status_badge} Server: {d.server_name}")
                    print(f"  Diff: {d.diff}")
            print("\n" + "=" * 70)

    if getattr(args, "strict_integrity", False) and has_strict_failure:
        sys.exit(2)
    if has_drift_failure:
        sys.exit(2)
    sys.exit(1 if report.has_critical_or_high else 0)


def handle_audit_typosquat(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.analyzers.typosquat import (
        RiskTier,
        TyposquatDetector,
        load_authentic_corpus,
    )

    corpus_path = (
        Path("docs/data/mcp_catalog_index.json")
        if Path("docs/data/mcp_catalog_index.json").exists()
        else None
    )
    corpus = load_authentic_corpus(corpus_path)
    detector = TyposquatDetector(corpus)

    config_path = Path(args.config)
    if not config_path.exists():
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to parse config file: {e}")
        sys.exit(1)

    mcp_servers = config_data.get("mcpServers", {})

    results = []
    typosquats_detected = []
    highest_risk = 0  # 0=Auth, 1=Susp, 2=High, 3=Crit
    risk_levels = {
        RiskTier.AUTHENTIC: 0,
        RiskTier.SUSPICIOUS: 1,
        RiskTier.HIGH: 2,
        RiskTier.CRITICAL: 3,
    }

    has_fixes = False

    for server_name, server_config in mcp_servers.items():
        command = server_config.get("command", "")
        args_list = server_config.get("args", [])

        package_name = None
        if command in ("npx", "uvx", "docker"):
            for arg in args_list:
                if not arg.startswith("-") and not arg.startswith("/") and arg != "run":
                    package_name = arg
                    break

        if not package_name:
            continue

        res = detector.analyze(package_name)

        res_dict = {
            "server_name": server_name,
            "package_name": res.package_name,
            "canonical_name": res.canonical_name,
            "risk_tier": res.risk_tier.value,
            "reason": res.reason,
            "distance": res.distance,
        }
        results.append(res_dict)

        if res.risk_tier != RiskTier.AUTHENTIC:
            typosquats_detected.append(res_dict)
            highest_risk = max(highest_risk, risk_levels[res.risk_tier])

            if args.fix and res.canonical_name:
                new_args = []
                for arg in args_list:
                    if arg == package_name:
                        new_args.append(res.canonical_name)
                    else:
                        new_args.append(arg)
                server_config["args"] = new_args
                has_fixes = True

    if args.fix and has_fixes:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
        if not args.output_json:
            logger.info(
                f"Fixed {len(typosquats_detected)} typosquatting packages in {config_path}"
            )

    if args.output_json:
        print(
            json.dumps(
                {
                    "analyzed_packages": results,
                    "typosquats_detected": typosquats_detected,
                    "risk_summary": {
                        "has_critical": highest_risk == 3,
                        "has_high": highest_risk >= 2,
                    },
                },
                indent=2,
            )
        )
    else:
        for r in typosquats_detected:
            logger.warning(
                f"Detected {r['risk_tier']} typosquat in server '{r['server_name']}': {r['package_name']} -> {r['canonical_name']} ({r['reason']})"
            )

    if highest_risk >= 2:  # HIGH or CRITICAL
        sys.exit(1)
    sys.exit(0)


def handle_audit_transitive(args: argparse.Namespace) -> None:
    auditor_cls = getattr(
        cli, "TransitiveDependencyAuditor", TransitiveDependencyAuditor
    )
    res = auditor_cls.audit_manifest_file(args.manifest)
    if getattr(args, "source_dir", None):
        from mcp_vulnerabilities.transitive import annotate_reachability

        res = annotate_reachability(
            res,
            args.source_dir,
            reachable_only=getattr(args, "reachable_only", False),
        )

    if args.severity_threshold:
        severity_order = {
            "LOW": 1,
            "MEDIUM": 2,
            "MODERATE": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        min_rank = severity_order.get(str(args.severity_threshold).upper(), 0)
        res.findings = [
            f
            for f in res.findings
            if severity_order.get(str(f.severity).upper(), 1) >= min_rank
        ]
    if args.format == "json":
        print(json.dumps(res.to_dict(), indent=2))
    elif args.format == "sarif":
        from mcp_vulnerabilities.audit.reporters import SarifReporter

        sarif_report = SarifReporter.generate_transitive_sarif(res)
        print(json.dumps(sarif_report, indent=2))
    else:
        print("\n" + "=" * 70)
        print(
            f" TRANSITIVE DEPENDENCY AUDIT: {res.target_manifest} ({res.total_dependencies} dependencies)"
        )
        print("=" * 70)
        if not res.findings:
            print(
                "✓ No known vulnerabilities found across third-party dependencies."
            )
        else:
            for f in res.findings:
                print(
                    f"\n[VULNERABLE DEPENDENCY] {f.dependency_name} ({f.ecosystem}) @ {f.installed_version or 'unpinned'}"
                )
                print(
                    f"  Vulnerability: {f.vulnerability_id} [Severity: {f.severity}]"
                    + (f" (CVSS {f.cvss_score})" if f.cvss_score else "")
                )
                if f.fixed_version:
                    print(f"  Remediation:   Upgrade to >= {f.fixed_version}")
                if getattr(f, "reachability", "UNKNOWN") != "UNKNOWN":
                    print(f"  Reachability:  {f.reachability}")
                if getattr(f, "reachable_from_tools", None):
                    print(
                        f"                 From Tools: {', '.join(f.reachable_from_tools)}"
                    )
                print(f"  Summary:       {f.summary}")
            print("\n" + "-" * 70)
            print(
                f"SUMMARY: {len(res.findings)} transitive vulnerabilities (Max CVSS: {res.max_cvss:.1f})."
            )
            print("-" * 70)

    sys.exit(1 if res.has_critical_or_high else 0)


def handle_hub(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.audit.hub import run_hub

    run_hub(args)


def handle_remediate_pr(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.bot.pr_builder import PRBuilder
    from mcp_vulnerabilities.bot.scanner import RepositoryScanner

    matcher_cls = getattr(cli, "VulnerabilityMatcher", VulnerabilityMatcher)

    snap_p = Path(args.snapshot)
    data_p = Path(args.data_dir)
    if snap_p.exists():
        matcher = matcher_cls.from_snapshot(snap_p)
    elif data_p.exists():
        matcher = matcher_cls.from_directory(data_p)
    else:
        logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
        sys.exit(2)

    scanner = RepositoryScanner(Path(args.repo_dir), matcher)
    plans = scanner.generate_plans()

    if not plans:
        if args.output_json:
            print(json.dumps({"status": "clean", "plans_created": 0}))
        else:
            print("No vulnerable MCP servers detected. Repository is clean.")
        sys.exit(0)

    pr_builder = PRBuilder(
        repo_root=Path(args.repo_dir),
        dry_run=args.dry_run,
        assignee=args.assignee,
        auto_merge=args.auto_merge,
    )

    for plan in plans:
        pr_builder.create_or_update_pr(plan)

    if args.output_json:
        print(json.dumps({"status": "success", "plans_created": len(plans)}))
    sys.exit(0)


def handle_fix(args: argparse.Namespace) -> None:
    matcher_cls = getattr(cli, "VulnerabilityMatcher", VulnerabilityMatcher)

    snap_p = Path(args.snapshot)
    data_p = Path(args.data_dir)
    if snap_p.exists():
        matcher = matcher_cls.from_snapshot(snap_p)
    elif data_p.exists():
        matcher = matcher_cls.from_directory(data_p)
    else:
        logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
        sys.exit(2)

    fixer = ClientConfigFixer(matcher)
    cfg_p = Path(args.config)

    try:
        result = fixer.fix_config(cfg_p, dry_run=args.dry_run)

        print("\n" + "=" * 70)
        print(" MCP CLIENT CONFIG REMEDIATION")
        print("=" * 70)

        if result["status"] == "no_servers_found":
            print("No MCP servers found in the configuration.")
        elif result["status"] == "no_changes_needed":
            print("✓ All scanned MCP servers are safe. No changes needed.")
        else:
            for change in result["changes"]:
                print(
                    f"Server: {change['server_name']} ({change['package_name']})"
                )
                print(f"  Old version: {change['old_version']}")
                print(f"  New version: {change['new_version']}")
                print()

            if args.dry_run:
                print("-" * 70)
                print("DRY RUN: No files were modified.")
            else:
                print("-" * 70)
                print("Configuration successfully updated.")
                print(f"Backup saved to: {result['backup_path']}")

    except Exception as e:
        logger.error("Failed to fix config: %s", e)
        sys.exit(1)


def handle_resolve_config(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.audit.conflict_resolver import (
        resolve_client_config,
    )

    try:
        result = resolve_client_config(
            config_path=args.config_file,
            strategy=args.strategy,
            output_path=args.output,
            passports_dir=args.dir,
        )
    except Exception as e:
        logger.error("Failed to resolve configuration conflicts: %s", e)
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)

    if args.json:
        print(json.dumps(result.resolved_config, indent=2))
    else:
        console.print("==================================================")
        console.print("         MCP CONFLICT RESOLUTION REPORT           ")
        console.print("==================================================")
        console.print(f"Strategy used:      {result.strategy_used}")
        console.print(f"Modifications made: {len(result.modifications_made)}")
        for mod in result.modifications_made:
            console.print(f"  - {mod}")
        console.print("==================================================")
        if not args.output:
            console.print("\nResolved Config Preview:")
            print(json.dumps(result.resolved_config, indent=2))


def handle_export_config(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.audit.config_exporter import export_client_config
    from mcp_vulnerabilities.catalog import load_passport_data

    passports = load_passport_data(
        args.dir if Path(args.dir).exists() else "data/passports.json.gz",
        as_specs=False,
    )
    passport_data = passports.get(args.package)

    if not passport_data:
        passport_data = {
            "package_name": args.package,
            "ecosystem": "npm",
            "versions": [],
        }

    config = export_client_config(passport_data, client=args.client)
    cfg_str = json.dumps(config, indent=2)
    if args.output:
        Path(args.output).write_text(cfg_str, encoding="utf-8")
        console.print(
            f"[bold green]Success:[/] Exported {args.client} config to {args.output}"
        )
    else:
        print(cfg_str)

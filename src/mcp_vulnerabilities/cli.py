"""CLI for MCP Vulnerability Ingestion Pipeline & Advisory Database."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from mcp_vulnerabilities.audit import ClientConfigParser, DiscoveredClientServer, VulnerabilityMatcher
from mcp_vulnerabilities.discovery import McpDiscoveryOrchestrator
from mcp_vulnerabilities.pipeline import McpVulnerabilityPipeline
from mcp_vulnerabilities.snapshot import build_snapshot
from mcp_vulnerabilities.transitive import TransitiveDependencyAuditor
from mcp_vulnerabilities.validator import OsvValidator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("mcp_vulnerabilities.cli")


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Vulnerability Advisory Database CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Discover
    disc_p = subparsers.add_parser("discover", help="Run multi-registry MCP server discovery")
    disc_p.add_argument("--catalog-file", default="data/mcp_servers.json", help="Output catalog path")
    disc_p.add_argument("--no-npm", action="store_true", help="Skip npm discovery")
    disc_p.add_argument("--no-pypi", action="store_true", help="Skip PyPI discovery")
    disc_p.add_argument("--no-github", action="store_true", help="Skip GitHub discovery")
    disc_p.add_argument("--no-registries", action="store_true", help="Skip crates/ruby/docker discovery")
    disc_p.add_argument("--no-smithery", action="store_true", help="Skip Smithery.ai discovery")
    disc_p.add_argument("--no-glama", action="store_true", help="Skip Glama.ai discovery")

    # Sync
    sync_p = subparsers.add_parser("sync", help="Run multi-source vulnerability ingestion pipeline")
    sync_p.add_argument("--output", default="data/vulnerabilities", help="Output directory")
    sync_p.add_argument("--state-file", default=None, help="State file path")
    sync_p.add_argument("--catalog-state-file", default="data/mcp_catalog_state.json", help="Version cache state path")
    sync_p.add_argument("--servers-catalog", default="data/mcp_servers.json", help="Servers catalog path")
    sync_p.add_argument("--markdown-dir", nargs="*", default=None, help="Markdown advisory directories")
    sync_p.add_argument("--cvelistv5-dir", nargs="*", default=None, help="CVEListV5 repository directories")
    sync_p.add_argument("--live-api", action="store_true", help="Query live GHSA and OSV.dev APIs")
    sync_p.add_argument("--cvelist-delta", action="store_true", help="Ingest recent CVE commits from GitHub")
    sync_p.add_argument("--reset-state", action="store_true", help="Reset sync state checkpoints")
    sync_p.add_argument("--snapshot", action="store_true", default=True, help="Compile snapshot after sync")


    # Validate
    val_p = subparsers.add_parser("validate", help="Validate OSV vulnerability files in directory")
    val_p.add_argument("--dir", default="data/vulnerabilities", help="Directory of OSV JSON files")

    # Snapshot
    snap_p = subparsers.add_parser("snapshot", help="Compile all advisories into consolidated .json.gz")
    snap_p.add_argument("--data-dir", default="data/vulnerabilities", help="Advisories data directory")
    snap_p.add_argument("--output-gz", default="vulnerabilities.json.gz", help="Output gzip file path")
    snap_p.add_argument("--output-json", default=None, help="Optional uncompressed JSON output path")

    # Audit
    aud_p = subparsers.add_parser("audit", help="Audit AI client MCP servers or packages against OSV database")
    aud_p.add_argument("--config", default=None, help="Path to AI client config file (e.g. claude_desktop_config.json)")
    aud_p.add_argument("--package", default=None, help="Specific package to audit, e.g. @modelcontextprotocol/server-neo4j@0.6.1")
    aud_p.add_argument("--data-dir", default="data/vulnerabilities", help="Directory of OSV advisories")
    aud_p.add_argument("--snapshot", default="vulnerabilities.json.gz", help="Path to consolidated snapshot file")
    aud_p.add_argument("--severity-threshold", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None, help="Minimum severity threshold")
    aud_p.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # Audit Transitive
    trans_p = subparsers.add_parser("audit-transitive", help="Audit third-party dependencies of MCP servers")
    trans_p.add_argument("--manifest", required=True, help="Path to package.json or requirements.txt")
    trans_p.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    args = parser.parse_args()

    if args.command == "discover":
        orchestrator = McpDiscoveryOrchestrator(catalog_file=args.catalog_file)
        servers = orchestrator.run_discovery(
            include_npm=not args.no_npm,
            include_pypi=not args.no_pypi,
            include_github=not args.no_github,
            include_other_registries=not args.no_registries,
            include_smithery=not args.no_smithery,
            include_glama=not args.no_glama,
        )
        print(f"Discovery complete. Discovered {len(servers)} MCP servers -> {args.catalog_file}")

    elif args.command == "sync":
        state_file = args.state_file or f"{args.output}/sync_state.json"
        pipeline = McpVulnerabilityPipeline(
            output_dir=args.output,
            state_file=state_file,
            catalog_state_file=args.catalog_state_file,
            servers_catalog_file=args.servers_catalog,
        )
        md_dirs = args.markdown_dir or ["tests/fixtures/osv/markdown"]
        cve5_dirs = args.cvelistv5_dir or (
            ["tests/fixtures/osv/cve_json5"] if not args.live_api else None
        )
        res = pipeline.run(
            include_markdown_dirs=md_dirs,
            include_cvelistv5_dirs=cve5_dirs,
            include_cvelist_delta=args.live_api or args.cvelist_delta,
            include_ghsa_api=args.live_api,
            include_osv_api=args.live_api,
            include_verity_catalog=True,
            offline_fallback_fixtures="tests/fixtures/osv" if not args.live_api else None,
            reset_checkpoints=args.reset_state,
        )
        logger.info(
            "Sync complete: collected=%d, merged=%d, emitted=%d, errors=%d",
            res.collected_count,
            res.merged_count,
            res.emitted_count,
            len(res.errors),
        )
        if args.snapshot:
            logger.info("Compiling consolidated snapshot...")
            build_snapshot(data_dir=args.output, output_gz=f"{Path(args.output).parent}/vulnerabilities.json.gz" if args.output != "data/vulnerabilities" else "vulnerabilities.json.gz")


    elif args.command == "validate":
        validator = OsvValidator()
        valid, invalid, errors = validator.validate_directory(args.dir)
        print(f"Validation summary: {valid} valid, {invalid} invalid advisories.")
        if invalid > 0:
            for err in errors:
                print(f"ERROR: {err}")
            sys.exit(1)
        sys.exit(0)

    elif args.command == "snapshot":
        res = build_snapshot(data_dir=args.data_dir, output_gz=args.output_gz, output_json=args.output_json)
        print(f"Compiled {res['total_vulnerabilities']} advisories ({res['size_kb']:.2f} KB) -> {res['snapshot_path']}")

    elif args.command == "audit":
        snap_p = Path(args.snapshot)
        data_p = Path(args.data_dir)
        if snap_p.exists():
            matcher = VulnerabilityMatcher.from_snapshot(snap_p)
        elif data_p.exists():
            matcher = VulnerabilityMatcher.from_directory(data_p)
        else:
            logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
            sys.exit(2)

        servers: List[DiscoveredClientServer] = []
        if args.package:
            spec = args.package.strip()
            eco = "npm" if spec.startswith("@") or not spec.startswith("mcp_") else "PyPI"
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
        elif args.config:
            cfg_p = Path(args.config)
            servers = ClientConfigParser.parse_file(cfg_p)
        else:
            standard_paths = ClientConfigParser.get_standard_config_paths()
            if not standard_paths:
                print("No standard AI client configuration files found. Provide one via --config <path> or audit a package with --package <spec>.")
                sys.exit(0)
            for path in standard_paths:
                logger.info("Found client config: %s", path)
                servers.extend(ClientConfigParser.parse_file(path))

        report = matcher.audit_servers(servers, severity_threshold=args.severity_threshold)

        if args.format == "json":
            import json
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print("\n" + "=" * 70)
            print(f" MCP SECURITY AUDIT REPORT: {len(report.scanned_servers)} servers scanned")
            print("=" * 70)
            if not report.findings:
                print("✓ No known vulnerabilities found across scanned MCP servers.")
            else:
                for f in report.findings:
                    status_badge = "[CONFIRMED VULNERABLE]" if f.is_confirmed else "[UNPINNED WARNING]"
                    print(f"\n{status_badge} Server: {f.server_name} ({f.package_name})")
                    print(f"  Vulnerability:   {f.vulnerability_id} [Severity: {f.severity_level}]")
                    if f.cvss_score:
                        print(f"  CVSS Score:      {f.cvss_score}")
                    print(f"  Installed:       {f.installed_version or 'Unpinned (latest)'}")
                    print(f"  Affected Range:  {f.affected_range}")
                    if f.fixed_version:
                        print(f"  Remediation:     Upgrade to >= {f.fixed_version}")
                    print(f"  Summary:         {f.summary}")
                    if f.references:
                        print(f"  References:      {f.references[0]}")
                print("\n" + "-" * 70)
                print(f"SUMMARY: {len(report.findings)} vulnerability findings ({'CRITICAL/HIGH issues detected!' if report.has_critical_or_high else 'No critical issues'}).")
                print("-" * 70)

        sys.exit(1 if report.has_critical_or_high else 0)

    elif args.command == "audit-transitive":
        res = TransitiveDependencyAuditor.audit_manifest_file(args.manifest)
        if args.format == "json":
            import json
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print("\n" + "=" * 70)
            print(f" TRANSITIVE DEPENDENCY AUDIT: {res.target_manifest} ({res.total_dependencies} dependencies)")
            print("=" * 70)
            if not res.findings:
                print("✓ No known vulnerabilities found across third-party dependencies.")
            else:
                for f in res.findings:
                    print(f"\n[VULNERABLE DEPENDENCY] {f.dependency_name} ({f.ecosystem}) @ {f.installed_version or 'unpinned'}")
                    print(f"  Vulnerability: {f.vulnerability_id} [Severity: {f.severity}]" + (f" (CVSS {f.cvss_score})" if f.cvss_score else ""))
                    if f.fixed_version:
                        print(f"  Remediation:   Upgrade to >= {f.fixed_version}")
                    print(f"  Summary:       {f.summary}")
                print("\n" + "-" * 70)
                print(f"SUMMARY: {len(res.findings)} transitive vulnerabilities (Max CVSS: {res.max_cvss:.1f}).")
                print("-" * 70)

        sys.exit(1 if res.has_critical_or_high else 0)


if __name__ == "__main__":
    main()

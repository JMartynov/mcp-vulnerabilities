"""Handlers for catalog querying, snapshots, search, lookup, and export."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.text import Text

from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher
from mcp_vulnerabilities.cli.common import console, logger
from mcp_vulnerabilities.provenance import resolve_provenance_urls
from mcp_vulnerabilities.snapshot import build_snapshot, export_osv_bucket
from mcp_vulnerabilities.threat_intel.epss import EpssClient
from mcp_vulnerabilities.validator import OsvValidator


def handle_site_build(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.site_builder import build_static_site_data

    workers = args.workers if args.workers > 0 else (os.cpu_count() or 4)

    build_static_site_data(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        passports_path=args.passports,
        workers=workers,
        use_cache=not args.no_cache,
        benchmark=args.benchmark,
    )
    sys.exit(0)


def handle_validate(args: argparse.Namespace) -> None:
    validator = OsvValidator()
    valid, invalid, errors = validator.validate_directory(args.dir)
    print(f"Validation summary: {valid} valid, {invalid} invalid advisories.")
    if invalid > 0:
        for err in errors:
            print(f"ERROR: {err}")
        sys.exit(1)
    sys.exit(0)


def handle_export_osv(args: argparse.Namespace) -> None:
    res = export_osv_bucket(data_dir=args.data_dir, output_dir=args.output_dir)
    print(
        f"Exported OSV bucket to {args.output_dir}: {res['count']} vulnerabilities, SHA256: {res['sha256']}"
    )


def handle_snapshot(args: argparse.Namespace) -> None:
    res = build_snapshot(
        data_dir=args.data_dir,
        output_gz=args.output_gz,
        output_json=args.output_json,
    )
    print(
        f"Compiled {res['total_vulnerabilities']} advisories ({res['size_kb']:.2f} KB) -> {res['snapshot_path']}"
    )


def handle_export_airgap(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.snapshot import export_airgap_bundle

    res = export_airgap_bundle(data_dir=args.data_dir, output_tar=args.output)
    print(
        f"Exported airgap bundle: {res['bundle_path']} (checksum: {res['checksum']})"
    )


def handle_search(args: argparse.Namespace) -> None:
    snap_p = Path(args.snapshot)
    data_p = Path(args.data_dir)
    if snap_p.exists():
        matcher = VulnerabilityMatcher.from_snapshot(snap_p)
    elif data_p.exists():
        matcher = VulnerabilityMatcher.from_directory(data_p)
    else:
        logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
        sys.exit(2)

    results = matcher.search(
        query=args.query, min_severity=args.min_severity, ecosystem=args.ecosystem
    )

    if args.format == "json":
        print(json.dumps([r.advisory.to_dict() for r in results], indent=2))
    else:
        print(f"\nSearch Results for '{args.query}'")
        print("=" * 70)
        if not results:
            print("No matching vulnerabilities found.")
        else:
            for r in results:
                adv = r.advisory

                for s in adv.severity:
                    pass  # Simplified, actual is handled in matcher via extract

                # More robust severity extraction:
                sev_str, _ = matcher._extract_severity_info(adv.to_dict())

                print(f"\nID:         {adv.id}")
                if adv.aliases:
                    print(f"Aliases:    {', '.join(adv.aliases)}")

                prov_urls = resolve_provenance_urls(adv.id, adv.aliases)
                print("Provenance:")
                if "cve" in prov_urls:
                    print(f"  * CVE:  {prov_urls['cve']}")
                if "nvd" in prov_urls:
                    print(f"  * NVD:  {prov_urls['nvd']}")
                if "ghsa" in prov_urls:
                    print(f"  * GHSA: {prov_urls['ghsa']}")
                print(f"  * OSV:  {prov_urls['osv']}")
                print(f"Severity:   {sev_str}")
                print(f"Matched On: {r.matched_on}")

                affected_pkgs: list[str] = []
                vuln_tools: list[str] = []
                for aff in adv.affected:
                    affected_pkgs.append(
                        f"{aff.package.name} ({aff.package.ecosystem})"
                    )
                    if (
                        aff.database_specific
                        and aff.database_specific.vulnerable_tools
                    ):
                        vuln_tools.extend(aff.database_specific.vulnerable_tools)

                if affected_pkgs:
                    print(f"Affected:   {', '.join(set(affected_pkgs))}")
                if vuln_tools:
                    print(f"Tools:      {', '.join(set(vuln_tools))}")

                print(f"Summary:    {adv.summary}")
        print("\n" + "=" * 70)
    sys.exit(0)


def handle_lookup(args: argparse.Namespace) -> None:
    snap_p = Path(args.snapshot)
    data_p = Path(args.data_dir)
    if snap_p.exists():
        matcher = VulnerabilityMatcher.from_snapshot(snap_p)
    elif data_p.exists():
        matcher = VulnerabilityMatcher.from_directory(data_p)
    else:
        logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
        sys.exit(2)

    adv = matcher.get_advisory(args.id_or_alias)

    if not adv:
        print(f"Vulnerability '{args.id_or_alias}' not found.")
        sys.exit(1)

    # Check EPSS
    cve_id = adv.id
    if not cve_id.startswith("CVE-"):
        for alias in adv.aliases:
            if alias.startswith("CVE-"):
                cve_id = alias
                break
    epss_client = EpssClient()
    epss_scores = (
        epss_client.get_scores([cve_id]) if cve_id.startswith("CVE-") else {}
    )
    epss = epss_scores.get(cve_id)

    if args.min_epss > 0.0:
        if not epss or epss.score < args.min_epss:
            print(
                f"Filtered out {adv.id}: EPSS score ({epss.score if epss else 0.0}) is below minimum {args.min_epss}."
            )
            sys.exit(0)

    if args.format == "json":
        print(json.dumps(adv.to_dict(), indent=2))
    else:
        print(f"\nVulnerability Details: {adv.id}")
        print("=" * 70)
        if adv.aliases:
            print(f"Aliases:    {', '.join(adv.aliases)}")

        sev_str, _ = matcher._extract_severity_info(adv.to_dict())
        print(f"Severity:   {sev_str}")
        print(f"Published:  {adv.published}")
        print(f"Modified:   {adv.modified}")
        if epss:
            c = Console()
            pct = epss.percentile * 100.0
            score_pct = epss.score * 100.0
            epss_color = (
                "red"
                if epss.score >= 0.35
                else "yellow"
                if epss.score >= 0.10
                else "cyan"
            )
            high_prob = " ⚠️ High Probability" if epss.is_high_risk else ""
            t = Text(
                f"EPSS:       {score_pct:.1f}% ({pct:.1f}th percentile{high_prob})",
                style=epss_color,
            )
            c.print(t)

        print(f"\nSummary:\n  {adv.summary}")
        print(
            f"\nDetails:\n  {adv.details[:500]}{'...' if len(adv.details) > 500 else ''}"
        )

        print("\nAffected Packages & Ranges:")
        for aff in adv.affected:
            print(f"  - {aff.package.name} ({aff.package.ecosystem})")
            for r in aff.ranges:
                events = []
                for ev in r.events:
                    if ev.introduced:
                        events.append(f">={ev.introduced}")
                    if ev.fixed:
                        events.append(f"<{ev.fixed}")
                    if ev.last_affected:
                        events.append(f"<={ev.last_affected}")
                print(f"    Range: {', '.join(events)}")
            if aff.database_specific and aff.database_specific.vulnerable_tools:
                print(
                    f"    Vulnerable Tools: {', '.join(aff.database_specific.vulnerable_tools)}"
                )

        if adv.references:
            print("\nReferences:")
            for ref in adv.references:
                print(f"  - {ref.url}")
        print("=" * 70)
    sys.exit(0)


def handle_timeline(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.catalog import load_passport_data
    from mcp_vulnerabilities.fingerprints.correlator import VulnerabilityCorrelator

    data_p = Path(args.data_dir)
    snap_p = Path(args.snapshot)
    passports_p = Path("data/passports.json.gz")
    passports = load_passport_data(passports_p)
    if not passports:
        console.print(
            f"[bold red]Error:[/] Passports file not found at {passports_p}. Please sync passports."
        )
        sys.exit(1)

    vp = snap_p if snap_p.exists() else data_p
    if vp.is_dir():
        matcher = VulnerabilityMatcher.from_directory(vp)
    else:
        matcher = VulnerabilityMatcher.from_snapshot(vp)
    correlator = VulnerabilityCorrelator(matcher=matcher, passports=passports)

    timeline = correlator.correlate_package(args.server)
    if not timeline:
        console.print(
            f"[bold red]Error:[/] Server '{args.server}' not found in passports."
        )
        sys.exit(1)

    console.print(
        f"\n[bold cyan]Vulnerability Timeline for {timeline.package_name} ({timeline.ecosystem})[/]\n"
    )

    for state in timeline.timeline:
        if args.target_version and args.target_version != state.version:
            continue

        v_str = (
            f"[bold red]{state.version} (VULNERABLE)[/]"
            if state.is_vulnerable
            else f"[bold green]{state.version} (SAFE)[/]"
        )
        console.print(f"• {v_str}")
        for adv in state.advisories:
            console.print(f"  - {adv.id}: {adv.summary}")

    console.print("")


def handle_verify_feed(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.attestation.manifest import (
        ChecksumMismatchError,
        verify_catalog_manifest,
    )
    from mcp_vulnerabilities.attestation.verifier import verify_sigstore_bundle

    feed_path = Path(args.feed)
    if not feed_path.exists():
        print(f"Error: Feed file not found: {feed_path}")
        sys.exit(3)

    if args.manifest:
        try:
            verify_catalog_manifest(Path(args.manifest).parent)
        except ChecksumMismatchError as e:
            print(f"Checksum mismatch error: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Manifest verification failed: {e}")
            sys.exit(3)

    if args.bundle:
        bundle_path = Path(args.bundle)
        if not bundle_path.exists():
            print(f"Error: Bundle file not found: {bundle_path}")
            sys.exit(3)

        try:
            result = verify_sigstore_bundle(
                target_path=feed_path,
                bundle_path=bundle_path,
                expected_identity=args.expected_identity,
                expected_issuer=args.expected_issuer,
                offline=args.offline,
            )

            if args.json:
                print(json.dumps(result))
            else:
                print(
                    f"Verification successful: {result['signer']} at {result['timestamp']}"
                )
            sys.exit(0)
        except Exception as e:
            print(f"Signature verification failed: {e}")
            sys.exit(2)
    else:
        print("Verified successfully (no bundle provided).")
        sys.exit(0)


def handle_correlate(args: argparse.Namespace) -> None:
    from mcp_vulnerabilities.catalog import load_passport_data
    from mcp_vulnerabilities.fingerprints.correlator import VulnerabilityCorrelator

    data_p = Path(args.data_dir)
    snap_p = Path(args.snapshot)
    passports_p = Path("data/passports.json.gz")
    passports = load_passport_data(passports_p)
    if not passports:
        console.print(
            f"[bold red]Error:[/] Passports file not found at {passports_p}. Please sync passports."
        )
        sys.exit(1)

    vp = snap_p if snap_p.exists() else data_p
    if vp.is_dir():
        matcher = VulnerabilityMatcher.from_directory(vp)
    else:
        matcher = VulnerabilityMatcher.from_snapshot(vp)
    correlator = VulnerabilityCorrelator(matcher=matcher, passports=passports)

    with console.status("Correlating all passports..."):
        results = correlator.correlate_all()

    out_data = [r.to_dict() for r in results]

    if args.output:
        with open(args.output, "w") as f:
            json.dump(out_data, f, indent=2)
        console.print(
            f"\n[bold green]Success:[/] Saved correlation dataset to {args.output}"
        )
    else:
        console.print(json.dumps(out_data, indent=2))

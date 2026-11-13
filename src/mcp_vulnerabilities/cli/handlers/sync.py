"""Handlers for discovery, enrichment, and sync pipelines."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mcp_vulnerabilities.cli.common import logger
from mcp_vulnerabilities.discovery import (
    CatalogVersionEnricher,
    McpDiscoveryOrchestrator,
)
from mcp_vulnerabilities.pipeline import McpVulnerabilityPipeline
from mcp_vulnerabilities.snapshot import build_snapshot


def handle_discover(args: argparse.Namespace) -> None:
    orchestrator = McpDiscoveryOrchestrator(catalog_file=args.catalog_file)
    servers = orchestrator.run_discovery(
        include_npm=not args.no_npm,
        include_pypi=not args.no_pypi,
        include_github=not args.no_github,
        include_other_registries=not args.no_registries,
        include_smithery=not args.no_smithery,
        include_glama=not args.no_glama,
        include_pruning=args.prune or args.prune_archived or args.prune_deleted,
        offline_backoff=args.offline_backoff,
    )
    print(
        f"Discovery complete. Discovered {len(servers)} MCP servers -> {args.catalog_file}"
    )


def handle_enrich(args: argparse.Namespace) -> None:
    enricher = CatalogVersionEnricher(
        catalog_file=args.catalog_file, max_workers=args.workers
    )
    stats = enricher.run_enrichment(limit=args.limit, force=args.force)
    print(
        f"Enriched {stats['attempted']} packages ({stats['updated']} updated, {stats['failed']} failed/skipped)"
    )


def handle_sync(args: argparse.Namespace) -> None:
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
        include_gitlab_dirs=args.gitlab_dir,
        include_cvelist_delta=args.live_api or args.cvelist_delta,
        include_ghsa_api=args.live_api,
        include_osv_api=args.live_api,
        include_nvd_api=args.live_api or args.nvd_api,
        include_gitlab_sync=args.include_gitlab,
        include_cisa_kev=True,
        include_verity_catalog=True,
        offline_fallback_fixtures="tests/fixtures/osv"
        if not args.live_api
        else None,
        reset_checkpoints=args.reset_state,
        include_pruning=args.prune or args.prune_archived or args.prune_deleted,
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
        build_snapshot(
            data_dir=args.output,
            output_gz=f"{Path(args.output).parent}/vulnerabilities.json.gz"
            if args.output != "data/vulnerabilities"
            else "vulnerabilities.json.gz",
        )

    if args.notify_webhooks and res.emitted_ids:
        logger.info("Checking newly emitted advisories for webhooks...")
        from mcp_vulnerabilities.notifier import ThreatFeedNotifier

        new_advs = []
        out_dir = Path(args.output)
        for adv_id in res.emitted_ids:
            try:
                fpath = out_dir / f"{adv_id}.json"
                if fpath.exists():
                    new_advs.append(json.loads(fpath.read_text(encoding="utf-8")))
            except Exception as exc:
                logger.warning(
                    "Failed to load emitted advisory %s: %s", adv_id, exc
                )
        if new_advs:
            ThreatFeedNotifier().process_and_notify(new_advs)

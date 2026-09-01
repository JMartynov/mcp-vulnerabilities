"""CLI for MCP Vulnerability Ingestion Pipeline & Advisory Database."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from mcp_vulnerabilities.pipeline import McpVulnerabilityPipeline
from mcp_vulnerabilities.snapshot import build_snapshot
from mcp_vulnerabilities.validator import OsvValidator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("mcp_vulnerabilities.cli")


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Vulnerability Advisory Database CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Sync
    sync_p = subparsers.add_parser("sync", help="Run multi-source vulnerability ingestion pipeline")
    sync_p.add_argument("--output", default="data/vulnerabilities", help="Output directory")
    sync_p.add_argument("--state-file", default=None, help="State file path")
    sync_p.add_argument("--markdown-dir", nargs="*", default=None, help="Markdown advisory directories")
    sync_p.add_argument("--cvelistv5-dir", nargs="*", default=None, help="CVEListV5 repository directories")
    sync_p.add_argument("--live-api", action="store_true", help="Query live GHSA and OSV.dev APIs")
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

    args = parser.parse_args()

    if args.command == "sync":
        state_file = args.state_file or f"{args.output}/sync_state.json"
        pipeline = McpVulnerabilityPipeline(output_dir=args.output, state_file=state_file)
        md_dirs = args.markdown_dir or ["tests/fixtures/osv/markdown"]
        cve5_dirs = args.cvelistv5_dir or (
            ["tests/fixtures/osv/cve_json5"] if not args.live_api else None
        )
        res = pipeline.run(
            include_markdown_dirs=md_dirs,
            include_cvelistv5_dirs=cve5_dirs,
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


if __name__ == "__main__":
    main()

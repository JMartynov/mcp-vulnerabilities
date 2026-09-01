"""Multi-source vulnerability ingestion and synchronization pipeline."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.converters.cve_json5 import CveJson5Converter
from mcp_vulnerabilities.converters.ghsa import GhsaConverter
from mcp_vulnerabilities.converters.markdown_cve import MarkdownAdvisoryConverter
from mcp_vulnerabilities.converters.nvd import NvdConverter
from mcp_vulnerabilities.converters.osv_dev import OsvDevConverter
from mcp_vulnerabilities.converters.verity import VerityCatalogConverter
from mcp_vulnerabilities.deduplicator import OsvDeduplicator
from mcp_vulnerabilities.filter import McpRelevanceFilter
from mcp_vulnerabilities.models import OsvVulnerability
from mcp_vulnerabilities.state import SyncStateManager
from mcp_vulnerabilities.validator import OsvValidator

logger = logging.getLogger("mcp_vulnerabilities.pipeline")

KNOWN_MCP_PACKAGES: tuple[tuple[str, str], ...] = (
    ("npm", "mcp-remote"),
    ("npm", "@modelcontextprotocol/server-postgres"),
    ("npm", "@modelcontextprotocol/server-sqlite"),
    ("npm", "@modelcontextprotocol/server-filesystem"),
    ("npm", "@modelcontextprotocol/server-github"),
    ("npm", "@modelcontextprotocol/server-git"),
    ("npm", "@modelcontextprotocol/server-brave-search"),
    ("npm", "@modelcontextprotocol/sdk"),
    ("npm", "@cyanheads/git-mcp-server"),
    ("npm", "sammcj/mcp-package-docs"),
    ("npm", "@aborruso/ckan-mcp-server"),
    ("npm", "mcp-server-figma"),
    ("PyPI", "mcp"),
    ("PyPI", "fastmcp"),
    ("PyPI", "mcp-neo4j-cypher"),
    ("PyPI", "mcp-server-sqlite"),
    ("PyPI", "mcp-server-git"),
    ("PyPI", "awslabs.aws-api-mcp-server"),
    ("Go", "github.com/modelcontextprotocol/go-sdk"),
)


@dataclass(frozen=True)
class PipelineResult:
    """Execution summary of vulnerability ingestion run."""

    collected_count: int
    merged_count: int
    emitted_count: int
    output_dir: str
    emitted_ids: tuple[str, ...]
    state_file: str
    errors: tuple[str, ...] = field(default_factory=tuple)


class McpVulnerabilityPipeline:
    """Orchestrates multi-source vulnerability collection, normalization, and persistence."""

    def __init__(
        self,
        output_dir: str | Path = "data/vulnerabilities",
        state_file: str | Path = "data/vulnerabilities/sync_state.json",
    ) -> None:
        self.output_dir = Path(output_dir)
        self.state_file = Path(state_file)
        self.state_manager = SyncStateManager(state_file=self.state_file)

    def run(
        self,
        include_markdown_dirs: list[str | Path] | None = None,
        include_cvelistv5_dirs: list[str | Path] | None = None,
        include_ghsa_api: bool = False,
        include_osv_api: bool = False,
        include_verity_catalog: bool = True,
        offline_fallback_fixtures: str | Path | None = None,
        reset_checkpoints: bool = False,
    ) -> PipelineResult:
        """Execute end-to-end ingestion pipeline with incremental state checkpointing."""
        if reset_checkpoints:
            self.state_manager = SyncStateManager(state_file=self.state_file)
            self.state_manager.state.sources.clear()

        collected: list[OsvVulnerability] = []
        errors: list[str] = []

        # 1. Ingest from internal Verity benchmark catalog
        if include_verity_catalog:
            try:
                verity_records = VerityCatalogConverter.convert_all()
                collected.extend(verity_records)
                self.state_manager.update_checkpoint(
                    "verity_catalog",
                    records_scanned=len(verity_records),
                    records_synced=len(verity_records),
                )
                logger.info(
                    "Ingested %d records from Verity Benchmark Catalog.", len(verity_records)
                )
            except Exception as exc:
                errors.append(f"VerityCatalog error: {exc}")

        # 2. Ingest from Markdown advisory directories
        if include_markdown_dirs:
            md_scanned = 0
            md_synced = 0
            for m_dir in include_markdown_dirs:
                path = Path(m_dir)
                if path.is_dir():
                    for md_file in sorted(path.glob("*.md")):
                        md_scanned += 1
                        try:
                            vuln = MarkdownAdvisoryConverter.from_file(md_file)
                            is_rel, _ = McpRelevanceFilter.is_relevant(
                                package_name=vuln.affected[0].package.name
                                if vuln.affected
                                else None,
                                summary=vuln.summary,
                                details=vuln.details,
                            )
                            if is_rel:
                                collected.append(vuln)
                                md_synced += 1
                        except Exception as exc:
                            errors.append(f"Markdown parse error in {md_file.name}: {exc}")
            self.state_manager.update_checkpoint(
                "markdown_curated",
                records_scanned=md_scanned,
                records_synced=md_synced,
            )

        # 3. Ingest from CVE JSON 5.x directories (cvelistV5) with checkpoint resumption
        if include_cvelistv5_dirs:
            cve_chk = self.state_manager.get_checkpoint("cvelist_v5")
            last_marker = cve_chk.last_marker
            cve_scanned = 0
            cve_synced = 0
            last_seen_marker = last_marker

            for c_dir in include_cvelistv5_dirs:
                path = Path(c_dir)
                if path.is_dir():
                    all_json_files = sorted(path.glob("**/*.json"))
                    for j_file in all_json_files:
                        if not j_file.name.startswith("CVE-"):
                            continue
                        file_rel_str = str(j_file.relative_to(path))
                        # Checkpoint filter: skip if already processed in prior run
                        if last_marker and file_rel_str <= last_marker:
                            continue

                        cve_scanned += 1
                        last_seen_marker = file_rel_str
                        try:
                            raw_data = json.loads(j_file.read_text(encoding="utf-8"))
                            if not isinstance(raw_data, dict):
                                continue
                            if raw_data.get("dataType") != "CVE_RECORD":
                                continue

                            # Evaluate MCP relevance
                            cna = raw_data.get("containers", {}).get("cna", {})
                            pkg_name = None
                            repo_url = None
                            for aff in cna.get("affected", []):
                                pkg_name = aff.get("packageName") or aff.get("product")
                                repo_url = aff.get("repo")
                                if pkg_name:
                                    break

                            desc_text = " ".join(
                                [d.get("value", "") for d in cna.get("descriptions", [])]
                            )

                            is_rel, reasons = McpRelevanceFilter.is_relevant(
                                package_name=pkg_name,
                                summary=desc_text[:200],
                                details=desc_text,
                                repo_url=repo_url,
                                raw_data=raw_data,
                            )
                            if is_rel:
                                vuln = CveJson5Converter.from_dict(raw_data)
                                collected.append(vuln)
                                cve_synced += 1
                                logger.debug(
                                    "Ingested MCP CVE JSON 5.x record %s (%s)",
                                    vuln.id,
                                    ", ".join(reasons),
                                )
                        except Exception as exc:
                            errors.append(f"CVE JSON 5.x error in {j_file.name}: {exc}")

            self.state_manager.update_checkpoint(
                "cvelist_v5",
                last_marker=last_seen_marker,
                records_scanned=cve_chk.records_scanned + cve_scanned,
                records_synced=cve_chk.records_synced + cve_synced,
            )

        # 4. Ingest from OSV.dev REST API for known packages
        if include_osv_api:
            for eco, pkg in KNOWN_MCP_PACKAGES:
                try:
                    osv_records = self._query_osv_dev(eco, pkg)
                    for r in osv_records:
                        is_rel, _ = McpRelevanceFilter.is_relevant(
                            package_name=pkg, summary=r.summary, details=r.details
                        )
                        if is_rel:
                            collected.append(r)
                except Exception as exc:
                    logger.debug("OSV.dev query error for %s/%s: %s", eco, pkg, exc)
            self.state_manager.update_checkpoint(
                "osv_dev",
                records_scanned=len(KNOWN_MCP_PACKAGES),
                records_synced=len(collected),
            )

        # 5. Ingest from offline fallback fixtures if specified
        if offline_fallback_fixtures:
            f_dir = Path(offline_fallback_fixtures)
            if f_dir.is_dir():
                for md_path in (f_dir / "markdown").glob("*.md"):
                    try:
                        v = MarkdownAdvisoryConverter.from_file(md_path)
                        is_rel, _ = McpRelevanceFilter.is_relevant(
                            package_name=v.affected[0].package.name if v.affected else None,
                            summary=v.summary,
                            details=v.details,
                        )
                        if is_rel:
                            collected.append(v)
                    except Exception as exc:
                        errors.append(f"Fixture markdown error: {exc}")

                for ghsa_path in (f_dir / "ghsa").glob("*.json"):
                    try:
                        data = json.loads(ghsa_path.read_text(encoding="utf-8"))
                        v = GhsaConverter.from_dict(data)
                        is_rel, _ = McpRelevanceFilter.is_relevant(
                            package_name=v.affected[0].package.name if v.affected else None,
                            summary=v.summary,
                            details=v.details,
                            raw_data=data,
                        )
                        if is_rel:
                            collected.append(v)
                    except Exception as exc:
                        errors.append(f"Fixture GHSA error: {exc}")

                for nvd_path in (f_dir / "nvd").glob("*.json"):
                    try:
                        data = json.loads(nvd_path.read_text(encoding="utf-8"))
                        v = NvdConverter.from_dict(data)
                        is_rel, _ = McpRelevanceFilter.is_relevant(
                            package_name=v.affected[0].package.name if v.affected else None,
                            summary=v.summary,
                            details=v.details,
                            raw_data=data,
                        )
                        if is_rel:
                            collected.append(v)
                    except Exception as exc:
                        errors.append(f"Fixture NVD error: {exc}")

                for osv_path in (f_dir / "osv_dev").glob("*.json"):
                    try:
                        data = json.loads(osv_path.read_text(encoding="utf-8"))
                        v = OsvDevConverter.from_dict(data)
                        is_rel, _ = McpRelevanceFilter.is_relevant(
                            package_name=v.affected[0].package.name if v.affected else None,
                            summary=v.summary,
                            details=v.details,
                        )
                        if is_rel:
                            collected.append(v)
                    except Exception as exc:
                        errors.append(f"Fixture OSV error: {exc}")

                for cve5_path in (f_dir / "cve_json5").glob("*.json"):
                    try:
                        data = json.loads(cve5_path.read_text(encoding="utf-8"))
                        cna = data.get("containers", {}).get("cna", {})
                        pkg_name = None
                        for aff in cna.get("affected", []):
                            pkg_name = aff.get("packageName") or aff.get("product")
                            if pkg_name:
                                break
                        desc_text = " ".join(
                            [d.get("value", "") for d in cna.get("descriptions", [])]
                        )
                        is_rel, _ = McpRelevanceFilter.is_relevant(
                            package_name=pkg_name,
                            summary=desc_text[:200],
                            details=desc_text,
                            raw_data=data,
                        )
                        if is_rel:
                            collected.append(CveJson5Converter.from_dict(data))
                    except Exception as exc:
                        errors.append(f"Fixture CVE JSON 5 error: {exc}")

        # 6. Deduplicate and merge
        merged = OsvDeduplicator.deduplicate_and_merge(collected)

        # 7. Validate each record and persist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        emitted_ids: list[str] = []
        index_entries: list[dict[str, Any]] = []

        for record in merged:
            val_errors = OsvValidator.validate(record)
            if val_errors:
                errors.append(f"Validation failed for {record.id}: {', '.join(val_errors)}")
                continue

            file_path = self.output_dir / f"{record.id}.json"
            file_path.write_text(record.to_json(), encoding="utf-8")
            emitted_ids.append(record.id)

            # Build search index entry
            pkgs = [
                {
                    "name": aff.package.name,
                    "ecosystem": aff.package.ecosystem,
                    "purl": aff.package.purl,
                    "severity": aff.database_specific.severity,
                    "cvss_score": aff.database_specific.cvss_score,
                }
                for aff in record.affected
            ]
            index_entries.append(
                {
                    "id": record.id,
                    "summary": record.summary,
                    "aliases": list(record.aliases),
                    "modified": record.modified,
                    "packages": pkgs,
                }
            )

        # Write index.json
        index_file = self.output_dir / "index.json"
        index_data = {
            "version": "1.0.0",
            "count": len(emitted_ids),
            "vulnerabilities": index_entries,
        }
        index_file.write_text(json.dumps(index_data, indent=2, sort_keys=True), encoding="utf-8")

        # Save sync checkpoints to disk
        self.state_manager.save()

        return PipelineResult(
            collected_count=len(collected),
            merged_count=len(merged),
            emitted_count=len(emitted_ids),
            output_dir=str(self.output_dir),
            emitted_ids=tuple(emitted_ids),
            state_file=str(self.state_file),
            errors=tuple(errors),
        )

    def _query_osv_dev(self, ecosystem: str, package_name: str) -> list[OsvVulnerability]:
        """Query live OSV.dev REST API for a package."""
        url = "https://api.osv.dev/v1/query"
        payload = json.dumps({"package": {"name": package_name, "ecosystem": ecosystem}}).encode(
            "utf-8"
        )
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "VerityRedTeam/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulns", [])
            return [OsvDevConverter.from_dict(v) for v in vulns]

"""Multi-source vulnerability ingestion and synchronization pipeline."""

from __future__ import annotations

import json
import logging
import os
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.catalog import McpCatalogState
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


def _get_github_headers() -> dict[str, str]:
    headers = {
        "User-Agent": "McpVulnerabilities/1.0 (Security Research; +https://github.com/JMartynov/mcp-vulnerabilities)",
        "Accept": "application/vnd.github.v3+json",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token.strip()}"
    return headers


def _get_ssl_context() -> ssl.SSLContext:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return ssl._create_unverified_context()


KNOWN_MCP_PACKAGES: tuple[tuple[str, str], ...] = (
    ("npm", "mcp-remote"),
    ("npm", "@modelcontextprotocol/server-postgres"),
    ("npm", "@modelcontextprotocol/server-sqlite"),
    ("npm", "@modelcontextprotocol/server-filesystem"),
    ("npm", "@modelcontextprotocol/server-github"),
    ("npm", "@modelcontextprotocol/server-git"),
    ("npm", "@modelcontextprotocol/server-brave-search"),
    ("npm", "@modelcontextprotocol/server-everything"),
    ("npm", "@modelcontextprotocol/sdk"),
    ("npm", "@cyanheads/git-mcp-server"),
    ("npm", "sammcj/mcp-package-docs"),
    ("npm", "@aborruso/ckan-mcp-server"),
    ("npm", "mcp-server-figma"),
    ("npm", "mcp-server-kubernetes"),
    ("npm", "excel-mcp-server"),
    ("npm", "mcp-framework"),
    ("PyPI", "mcp"),
    ("PyPI", "fastmcp"),
    ("PyPI", "mcp-neo4j-cypher"),
    ("PyPI", "mcp-server-sqlite"),
    ("PyPI", "mcp-server-git"),
    ("PyPI", "awslabs.aws-api-mcp-server"),
    ("PyPI", "mcp-server-kubernetes"),
    ("Go", "github.com/modelcontextprotocol/go-sdk"),
    ("crates.io", "rust-mcp-sdk"),
    ("crates.io", "rmcp"),
    ("RubyGems", "mcp"),
    ("RubyGems", "fast-mcp"),
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
        catalog_state_file: str | Path = "data/mcp_catalog_state.json",
        servers_catalog_file: str | Path = "data/mcp_servers.json",
    ) -> None:
        self.output_dir = Path(output_dir)
        self.state_file = Path(state_file)
        self.state_manager = SyncStateManager(state_file=self.state_file)
        self.catalog_state = McpCatalogState(state_file=catalog_state_file)
        self.servers_catalog_file = Path(servers_catalog_file)

    def run(
        self,
        include_markdown_dirs: list[str | Path] | None = None,
        include_cvelistv5_dirs: list[str | Path] | None = None,
        include_cvelist_delta: bool = False,
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
            self.catalog_state.records.clear()

        collected: list[OsvVulnerability] = []
        errors: list[str] = []

        # 0. Pre-load historical advisories
        if not reset_checkpoints and self.output_dir.is_dir():
            for j_file in self.output_dir.glob("*.json"):
                if j_file.name in ("index.json", "sync_state.json"):
                    continue
                try:
                    data = json.loads(j_file.read_text(encoding="utf-8"))
                    collected.append(OsvVulnerability.from_dict(data))
                except Exception as exc:
                    errors.append(f"Failed to load historical advisory {j_file.name}: {exc}")

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
            last_scan_dt = None
            if cve_chk.last_scan_utc:
                try:
                    import datetime
                    last_scan_dt = datetime.datetime.fromisoformat(cve_chk.last_scan_utc).replace(tzinfo=datetime.timezone.utc)
                except Exception:
                    pass

            for c_dir in include_cvelistv5_dirs:
                path = Path(c_dir)
                if path.is_dir():
                    all_json_files = sorted(path.glob("**/*.json"))
                    for j_file in all_json_files:
                        if not j_file.name.startswith("CVE-"):
                            continue
                        file_rel_str = str(j_file.relative_to(path))
                        # Checkpoint filter: skip if already processed in prior run
                        # Unless the file has been modified since the last scan
                        skip_file = False
                        if last_marker and file_rel_str <= last_marker:
                            skip_file = True
                            if last_scan_dt:
                                try:
                                    import datetime
                                    mtime = j_file.stat().st_mtime
                                    mtime_dt = datetime.datetime.fromtimestamp(mtime, datetime.timezone.utc)
                                    if mtime_dt > last_scan_dt:
                                        skip_file = False
                                except Exception:
                                    pass
                        if skip_file:
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

        # 4. Ingest from GitHub Security Advisories (GHSA) live REST API
        if include_ghsa_api:
            ghsa_chk = self.state_manager.get_checkpoint("ghsa_api")
            last_updated_at = ghsa_chk.last_updated_at
            
            ghsa_scanned = 0
            ghsa_synced = 0
            newest_advisory_updated_at = last_updated_at

            try:
                base_ghsa_url = "https://api.github.com/advisories?per_page=100&direction=desc&sort=updated"
                if last_updated_at:
                    base_ghsa_url += f"&since={last_updated_at}"
                
                next_url = base_ghsa_url
                pages_fetched = 0
                max_pages = 5

                while next_url and pages_fetched < max_pages:
                    req = urllib.request.Request(
                        next_url,
                        headers=_get_github_headers(),
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=12.0, context=_get_ssl_context()) as resp:
                            data = json.loads(resp.read().decode("utf-8"))
                            
                            if isinstance(data, list):
                                ghsa_scanned += len(data)
                                for adv in data:
                                    adv_updated_at = adv.get("updated_at")
                                    if adv_updated_at:
                                        if not newest_advisory_updated_at or adv_updated_at > newest_advisory_updated_at:
                                            newest_advisory_updated_at = adv_updated_at
                                        
                                    pkg_name = adv.get("vulnerabilities", [{}])[0].get("package", {}).get("name")
                                    is_rel, _ = McpRelevanceFilter.is_relevant(
                                        package_name=pkg_name,
                                        summary=adv.get("summary", ""),
                                        details=adv.get("description", ""),
                                        raw_data=adv,
                                    )
                                    if is_rel:
                                        try:
                                            vuln = GhsaConverter.from_dict(adv)
                                            collected.append(vuln)
                                            ghsa_synced += 1
                                            # Invalidate package in catalog state so full context is refreshed
                                            for aff in vuln.affected:
                                                self.catalog_state.mark_stale(aff.package.ecosystem, aff.package.name)
                                        except Exception as conv_e:
                                            logger.debug("GHSA conversion error: %s", conv_e)
                            
                            next_url = None
                            link_header = resp.headers.get("Link")
                            if link_header:
                                links = link_header.split(",")
                                for link in links:
                                    if 'rel="next"' in link:
                                        start_idx = link.find("<") + 1
                                        end_idx = link.find(">")
                                        if start_idx > 0 and end_idx > start_idx:
                                            next_url = link[start_idx:end_idx]
                                        break
                    except urllib.error.HTTPError as e:
                        if e.code in (403, 429):
                            logger.error(f"GitHub API rate limit exceeded ({e.code}). Please configure GITHUB_TOKEN to elevate quotas.")
                            break
                        raise
                    
                    pages_fetched += 1

                self.state_manager.update_checkpoint(
                    "ghsa_api",
                    last_updated_at=newest_advisory_updated_at,
                    records_scanned=ghsa_chk.records_scanned + ghsa_scanned,
                    records_synced=ghsa_chk.records_synced + ghsa_synced,
                )
                logger.info("GHSA live API ingestion: scanned=%d, synced=%d", ghsa_scanned, ghsa_synced)
            except Exception as exc:
                errors.append(f"GHSA API ingestion error: {exc}")

        # 5. Ingest from CVEListV5 GitHub Commits delta stream
        if include_cvelist_delta:
            cve_delta_chk = self.state_manager.get_checkpoint("cvelist_delta")
            last_marker = cve_delta_chk.last_marker
            
            cve_delta_scanned = 0
            cve_delta_synced = 0
            newest_head_sha = last_marker

            try:
                cve_delta_url = "https://api.github.com/repos/CVEProject/cvelistV5/commits?per_page=5"
                req = urllib.request.Request(
                    cve_delta_url,
                    headers=_get_github_headers(),
                )
                try:
                    with urllib.request.urlopen(req, timeout=12.0, context=_get_ssl_context()) as resp:
                        commits = json.loads(resp.read().decode("utf-8"))
                        if isinstance(commits, list) and commits:
                            newest_head_sha = commits[0]["sha"]
                            
                            for commit in commits:
                                commit_sha = commit["sha"]
                                if last_marker and commit_sha == last_marker:
                                    break
                                    
                                detail_url = f"https://api.github.com/repos/CVEProject/cvelistV5/commits/{commit_sha}"
                                detail_req = urllib.request.Request(
                                    detail_url,
                                    headers=_get_github_headers(),
                                )
                                try:
                                    with urllib.request.urlopen(detail_req, timeout=12.0, context=_get_ssl_context()) as d_resp:
                                        detail = json.loads(d_resp.read().decode("utf-8"))
                                        for f_item in detail.get("files", []):
                                            f_name = f_item.get("filename", "")
                                            if f_name.endswith(".json") and "CVE-" in f_name:
                                                cve_delta_scanned += 1
                                                raw_url = f_item.get("raw_url")
                                                if raw_url:
                                                    try:
                                                        with urllib.request.urlopen(raw_url, timeout=5.0, context=_get_ssl_context()) as r_resp:
                                                            raw_cve = json.loads(r_resp.read().decode("utf-8"))
                                                            cna = raw_cve.get("containers", {}).get("cna", {})
                                                            desc_val = " ".join([d.get("value", "") for d in cna.get("descriptions", [])])
                                                            is_rel, _ = McpRelevanceFilter.is_relevant(
                                                                summary=desc_val[:200],
                                                                details=desc_val,
                                                                raw_data=raw_cve,
                                                            )
                                                            if is_rel:
                                                                collected.append(CveJson5Converter.from_dict(raw_cve))
                                                                cve_delta_synced += 1
                                                    except Exception as cve_fetch_err:
                                                        logger.debug("Failed to fetch raw CVE %s: %s", f_name, cve_fetch_err)
                                except urllib.error.HTTPError as e:
                                    if e.code in (403, 429):
                                        logger.error(f"GitHub API rate limit exceeded ({e.code}) while fetching commit {commit_sha}. Please configure GITHUB_TOKEN.")
                                        break
                                    raise
                except urllib.error.HTTPError as e:
                    if e.code in (403, 429):
                        logger.error(f"GitHub API rate limit exceeded ({e.code}). Please configure GITHUB_TOKEN to elevate quotas.")
                    else:
                        raise
                self.state_manager.update_checkpoint(
                    "cvelist_delta",
                    last_marker=newest_head_sha,
                    records_scanned=cve_delta_chk.records_scanned + cve_delta_scanned,
                    records_synced=cve_delta_chk.records_synced + cve_delta_synced,
                )
                logger.info("CVEListV5 delta ingestion: scanned=%d, synced=%d", cve_delta_scanned, cve_delta_synced)
            except Exception as exc:
                errors.append(f"CVEListV5 delta error: {exc}")

        # 6. Ingest from OSV.dev REST/Batch API with Version-Aware Caching
        if include_osv_api:
            candidate_map: dict[tuple[str, str], str] = {}
            if self.servers_catalog_file.exists():
                try:
                    cat_data = json.loads(self.servers_catalog_file.read_text(encoding="utf-8"))
                    for s in cat_data.get("servers", {}).values():
                        eco = s.get("ecosystem", "")
                        name = s.get("name", "")
                        ver = s.get("version", "")
                        if eco and name and eco in ("npm", "PyPI", "crates.io", "RubyGems"):
                            candidate_map[(eco, name)] = ver
                except Exception as cat_e:
                    logger.debug("Catalog file parse error: %s", cat_e)

            for eco, pkg in KNOWN_MCP_PACKAGES:
                if (eco, pkg) not in candidate_map:
                    candidate_map[(eco, pkg)] = ""

            candidates_to_query = [
                {"ecosystem": eco, "name": name, "version": ver}
                for (eco, name), ver in candidate_map.items()
                if self.catalog_state.should_query(eco, name, ver or None)
            ]
            skipped_count = len(candidate_map) - len(candidates_to_query)
            logger.info(
                "OSV Batch Ingestion: Total candidates=%d, Needs audit=%d, Cached skips=%d",
                len(candidate_map),
                len(candidates_to_query),
                skipped_count,
            )

            batch_size = 50
            osv_synced = 0
            for i in range(0, len(candidates_to_query), batch_size):
                chunk = candidates_to_query[i : i + batch_size]
                try:
                    res_map = self._query_osv_batch(chunk)
                    for item in chunk:
                        c_key = f"{item['ecosystem'].lower()}:{item['name'].lower()}"
                        vulns = res_map.get(c_key, [])
                        vuln_ids = []
                        for v in vulns:
                            is_rel, _ = McpRelevanceFilter.is_relevant(
                                package_name=item["name"],
                                summary=v.summary,
                                details=v.details,
                            )
                            if is_rel:
                                collected.append(v)
                                vuln_ids.append(v.id)
                                osv_synced += 1
                        self.catalog_state.update_record(
                            ecosystem=item["ecosystem"],
                            name=item["name"],
                            version=item["version"],
                            vulnerabilities=vuln_ids,
                        )
                except Exception as exc:
                    errors.append(f"OSV batch query error: {exc}")

            self.catalog_state.save()
            self.state_manager.update_checkpoint(
                "osv_dev",
                records_scanned=len(candidates_to_query),
                records_synced=osv_synced,
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
        tmp_index_file = self.output_dir / "index.json.tmp"
        tmp_index_file.write_text(json.dumps(index_data, indent=2, sort_keys=True), encoding="utf-8")
        tmp_index_file.replace(index_file)

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
        with urllib.request.urlopen(req, timeout=5.0, context=_get_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulns", [])
            return [OsvDevConverter.from_dict(v) for v in vulns]

    def _query_osv_batch(
        self, packages: list[dict[str, str]]
    ) -> dict[str, list[OsvVulnerability]]:
        """Query OSV.dev /v1/querybatch and return mapping by package key."""
        if not packages:
            return {}
        url = "https://api.osv.dev/v1/querybatch"
        payload = json.dumps(
            {
                "queries": [
                    {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}}
                    for p in packages
                ]
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "McpVulnerabilities/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15.0, context=_get_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results = data.get("results", [])
            mapping: dict[str, list[OsvVulnerability]] = {}
            for pkg, res in zip(packages, results):
                key = f"{pkg['ecosystem'].lower()}:{pkg['name'].lower()}"
                raw_vulns = res.get("vulns", [])
                converted = []
                for v in raw_vulns:
                    try:
                        converted.append(OsvDevConverter.from_dict(v))
                    except Exception as conv_err:
                        logger.debug("Failed to convert OSV item: %s", conv_err)
                mapping[key] = converted
            return mapping


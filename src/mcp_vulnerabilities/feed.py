"""Threat feed generators producing Atom 1.0 XML and JSON Feed 1.1 for MCP security advisories."""

from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

FEED_TITLE = "Model Context Protocol (MCP) Security Advisories"
FEED_HOMEPAGE = "https://github.com/JMartynov/mcp-vulnerabilities"
FEED_DESCRIPTION = "Real-time feed of OSV-compliant security advisories, CVEs, and vulnerabilities across MCP servers."


class AdvisoryFeedBuilder:
    """Builds Atom 1.0 XML and JSON Feed 1.1 artifacts from OSV advisories."""

    @classmethod
    def sort_advisories(cls, advisories: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sorts advisories by published or modified timestamp descending."""
        def get_timestamp(adv: dict[str, Any]) -> str:
            return adv.get("published") or adv.get("modified") or "1970-01-01T00:00:00Z"

        return sorted(advisories, key=get_timestamp, reverse=True)

    @classmethod
    def generate_atom_feed(
        cls,
        advisories: list[dict[str, Any]],
        output_path: str | Path,
        max_items: int = 100,
    ) -> Path:
        """Generates an RFC 4287 compliant Atom 1.0 XML feed."""
        sorted_advs = cls.sort_advisories(advisories)[:max_items]
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)

        ns = "http://www.w3.org/2005/Atom"
        ET.register_namespace("", ns)
        feed = ET.Element(f"{{{ns}}}feed")

        # Feed metadata
        title = ET.SubElement(feed, f"{{{ns}}}title")
        title.text = FEED_TITLE

        subtitle = ET.SubElement(feed, f"{{{ns}}}subtitle")
        subtitle.text = FEED_DESCRIPTION

        feed_id = ET.SubElement(feed, f"{{{ns}}}id")
        feed_id.text = f"{FEED_HOMEPAGE}/feed.atom"

        link_self = ET.SubElement(feed, f"{{{ns}}}link")
        link_self.set("rel", "self")
        link_self.set("href", f"{FEED_HOMEPAGE}/raw/main/data/feed.atom")

        link_alt = ET.SubElement(feed, f"{{{ns}}}link")
        link_alt.set("rel", "alternate")
        link_alt.set("href", FEED_HOMEPAGE)

        updated = ET.SubElement(feed, f"{{{ns}}}updated")
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if sorted_advs:
            updated.text = sorted_advs[0].get("modified") or sorted_advs[0].get("published") or now_iso
        else:
            updated.text = now_iso

        author = ET.SubElement(feed, f"{{{ns}}}author")
        author_name = ET.SubElement(author, f"{{{ns}}}name")
        author_name.text = "MCP Security Community"

        # Entries
        for adv in sorted_advs:
            entry = ET.SubElement(feed, f"{{{ns}}}entry")

            adv_id = adv.get("id", "UNKNOWN")
            severity, cvss = cls._extract_severity_info(adv)
            summary = adv.get("summary") or adv.get("details", "")[:140]

            entry_id = ET.SubElement(entry, f"{{{ns}}}id")
            entry_id.text = f"urn:mcp:vulnerability:{adv_id}"

            entry_title = ET.SubElement(entry, f"{{{ns}}}title")
            entry_title.text = f"[{severity}] {adv_id}: {summary}"

            # Entry link to reference or GitHub repo
            canonical_url = cls._extract_canonical_url(adv)
            entry_link = ET.SubElement(entry, f"{{{ns}}}link")
            entry_link.set("rel", "alternate")
            entry_link.set("href", canonical_url)

            entry_updated = ET.SubElement(entry, f"{{{ns}}}updated")
            entry_updated.text = adv.get("modified") or adv.get("published") or now_iso

            if adv.get("published"):
                entry_pub = ET.SubElement(entry, f"{{{ns}}}published")
                entry_pub.text = adv["published"]

            entry_summary = ET.SubElement(entry, f"{{{ns}}}summary")
            entry_summary.text = summary

            entry_content = ET.SubElement(entry, f"{{{ns}}}content")
            entry_content.set("type", "html")
            entry_content.text = cls._build_html_content(adv, severity, cvss)

        tree = ET.ElementTree(feed)
        ET.indent(tree, space="  ")
        tree.write(out_p, encoding="utf-8", xml_declaration=True)
        logger.info("Compiled Atom 1.0 feed with %d entries -> %s", len(sorted_advs), out_p)
        return out_p

    @classmethod
    def generate_json_feed(
        cls,
        advisories: list[dict[str, Any]],
        output_path: str | Path,
        max_items: int = 100,
    ) -> Path:
        """Generates a JSON Feed 1.1 compliant feed."""
        sorted_advs = cls.sort_advisories(advisories)[:max_items]
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)

        items = []
        for adv in sorted_advs:
            adv_id = adv.get("id", "UNKNOWN")
            severity, cvss = cls._extract_severity_info(adv)
            summary = adv.get("summary") or adv.get("details", "")[:140]
            canonical_url = cls._extract_canonical_url(adv)

            items.append({
                "id": f"urn:mcp:vulnerability:{adv_id}",
                "url": canonical_url,
                "title": f"[{severity}] {adv_id}: {summary}",
                "summary": summary,
                "content_html": cls._build_html_content(adv, severity, cvss),
                "date_published": adv.get("published"),
                "date_modified": adv.get("modified"),
                "tags": [severity, *(cls._extract_packages(adv))],
            })

        feed_data = {
            "version": "https://jsonfeed.org/version/1.1",
            "title": FEED_TITLE,
            "home_page_url": FEED_HOMEPAGE,
            "feed_url": f"{FEED_HOMEPAGE}/raw/main/data/feed.json",
            "description": FEED_DESCRIPTION,
            "items": items,
        }

        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(feed_data, f, indent=2, ensure_ascii=False)

        logger.info("Compiled JSON Feed 1.1 with %d entries -> %s", len(sorted_advs), out_p)
        return out_p

    @staticmethod
    def _extract_canonical_url(adv: dict[str, Any]) -> str:
        for ref in adv.get("references", []):
            url = ref.get("url", "")
            if "github.com" in url or "nvd.nist.gov" in url:
                return url
        return f"{FEED_HOMEPAGE}/blob/main/data/vulnerabilities/{adv.get('id', 'index')}.json"

    @staticmethod
    def _extract_packages(adv: dict[str, Any]) -> list[str]:
        names = []
        for aff in adv.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("name"):
                names.append(pkg["name"])
        return names

    @staticmethod
    def _extract_severity_info(adv: dict[str, Any]) -> tuple[str, float | None]:
        cvss_score = None
        for s in adv.get("severity", []):
            try:
                cvss_score = float(s.get("score"))
                break
            except (ValueError, TypeError):
                pass

        db_spec = adv.get("database_specific", {})
        if not db_spec and adv.get("affected"):
            db_spec = adv["affected"][0].get("database_specific", {})

        sev = db_spec.get("severity")
        if not sev and cvss_score:
            if cvss_score >= 9.0:
                sev = "CRITICAL"
            elif cvss_score >= 7.0:
                sev = "HIGH"
            elif cvss_score >= 4.0:
                sev = "MEDIUM"
            else:
                sev = "LOW"
        return (sev or "UNKNOWN").upper(), cvss_score

    @classmethod
    def _build_html_content(cls, adv: dict[str, Any], severity: str, cvss: float | None) -> str:
        adv_id = adv.get("id", "UNKNOWN")
        details = adv.get("details", "")
        pkg_names = ", ".join(cls._extract_packages(adv)) or "Unknown MCP Server"

        html = [
            f"<p><strong>Vulnerability ID:</strong> {adv_id}</p>",
            f"<p><strong>Severity:</strong> {severity}" + (f" (CVSS {cvss})" if cvss else "") + "</p>",
            f"<p><strong>Affected Package(s):</strong> {pkg_names}</p>",
            f"<p><strong>Details:</strong><br>{details}</p>",
        ]

        refs = [r.get("url") for r in adv.get("references", []) if r.get("url")]
        if refs:
            html.append("<p><strong>References:</strong><ul>")
            for r in refs[:4]:
                html.append(f'<li><a href="{r}">{r}</a></li>')
            html.append("</ul></p>")

        return "\n".join(html)

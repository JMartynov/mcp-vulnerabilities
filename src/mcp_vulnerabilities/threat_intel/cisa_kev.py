"""CISA Known Exploited Vulnerabilities (KEV) Client."""

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from mcp_vulnerabilities.ssl_utils import get_ssl_context

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CisaKevRecord:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_campaign_use: str  # "Known" | "Unknown"
    notes: str = ""


class CisaKevClient:
    """Client for ingesting and caching the CISA KEV catalog."""

    FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    USER_AGENT = "mcp-vulnerabilities/1.2.0 (+https://github.com/JMartynov/mcp-vulnerabilities)"

    def __init__(self, data_dir: str | Path = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.data_dir / "cisa_kev.json"
        self.meta_file = self.data_dir / "cisa_kev_cache_meta.json"
        self._records: dict[str, CisaKevRecord] = {}
        self._loaded = False

    def sync(self) -> dict[str, CisaKevRecord]:
        """Fetches or reloads catalog and updates cache."""
        headers = {"User-Agent": self.USER_AGENT}
        meta = {}

        if self.meta_file.exists():
            try:
                meta = json.loads(self.meta_file.read_text(encoding="utf-8"))
                if meta.get("etag"):
                    headers["If-None-Match"] = meta["etag"]
                if meta.get("last_modified"):
                    headers["If-Modified-Since"] = meta["last_modified"]
            except Exception as e:
                logger.warning("Failed to read KEV cache metadata: %s", e)

        req = urllib.request.Request(self.FEED_URL, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15.0, context=get_ssl_context()) as resp:
                data = resp.read()

                # Update meta
                new_etag = resp.headers.get("ETag")
                new_last_modified = resp.headers.get("Last-Modified")
                if new_etag or new_last_modified:
                    self.meta_file.write_text(
                        json.dumps({"etag": new_etag, "last_modified": new_last_modified}),
                        encoding="utf-8"
                    )

                # Save cache
                self.cache_file.write_bytes(data)

                # Parse
                parsed_data = json.loads(data.decode("utf-8"))
                self._parse_and_load(parsed_data)

        except urllib.error.HTTPError as e:
            if e.code == 304:
                logger.debug("CISA KEV catalog not modified (304), using cache.")
                self._load_from_cache()
            else:
                logger.error("HTTP error fetching CISA KEV: %s", e)
                self._load_from_cache()
        except Exception as e:
            logger.error("Error fetching CISA KEV (falling back to cache): %s", e)
            self._load_from_cache()

        return self._records

    def _load_from_cache(self):
        if not self.cache_file.exists():
            logger.warning("No CISA KEV cache found.")
            return

        try:
            parsed_data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            self._parse_and_load(parsed_data)
        except Exception as e:
            logger.error("Failed to load CISA KEV cache: %s", e)

    def _parse_and_load(self, data: dict):
        self._records.clear()
        for v in data.get("vulnerabilities", []):
            cve_id = str(v.get("cveID", "")).upper()
            if not cve_id:
                continue

            record = CisaKevRecord(
                cve_id=cve_id,
                vendor_project=v.get("vendorProject", ""),
                product=v.get("product", ""),
                vulnerability_name=v.get("vulnerabilityName", ""),
                date_added=v.get("dateAdded", ""),
                short_description=v.get("shortDescription", ""),
                required_action=v.get("requiredAction", ""),
                due_date=v.get("dueDate", ""),
                known_ransomware_campaign_use=v.get("knownRansomwareCampaignUse", "Unknown"),
                notes=v.get("notes", "")
            )
            self._records[cve_id] = record
        self._loaded = True

    def get_record(self, cve_id: str) -> CisaKevRecord | None:
        """O(1) indexed lookup by normalized uppercase CVE ID."""
        if not self._loaded:
            self._load_from_cache()
        return self._records.get(cve_id.upper())

    def is_known_exploited(self, cve_id_or_alias: str) -> bool:
        """Checks if ID or any alias matches KEV."""
        return self.get_record(cve_id_or_alias) is not None

    def get_all_cves(self) -> set[str]:
        """Returns set of all active KEV CVE IDs."""
        if not self._loaded:
            self._load_from_cache()
        return set(self._records.keys())

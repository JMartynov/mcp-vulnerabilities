import json
import logging
import urllib.request
import urllib.error
import ssl
import zipfile
import io
from pathlib import Path

from mcp_vulnerabilities.converters.openssf_malware import MaliciousPackageRecord, OpenSsfMalwareConverter
from mcp_vulnerabilities.pipeline import is_version_affected
from mcp_vulnerabilities.models import RangeSpec, EventSpec, RangeType

logger = logging.getLogger(__name__)

class OpenSsfMaliciousSync:
    _records_cache: dict[str, tuple[float, dict[str, MaliciousPackageRecord]]] = {}

    def __init__(self, data_path: Path | str = "data/malicious_packages.json"):
        self.data_path = Path(data_path)
        self.records: dict[str, MaliciousPackageRecord] = {}
        self.load()

    def load(self):
        if self.data_path.exists():
            try:
                path_str = str(self.data_path.resolve())
                mtime = self.data_path.stat().st_mtime
                if path_str in self._records_cache and self._records_cache[path_str][0] == mtime:
                    self.records = self._records_cache[path_str][1].copy()
                    return

                data = json.loads(self.data_path.read_text(encoding="utf-8"))
                for record_dict in data:
                    record = MaliciousPackageRecord(**record_dict)
                    key = f"{record.ecosystem.lower()}::{record.package_name}"
                    self.records[key] = record
                self._records_cache[path_str] = (mtime, self.records.copy())
            except Exception as e:
                logger.error(f"Failed to load malicious packages from {self.data_path}: {e}")

    def save(self):
        self.data_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = [vars(record) for record in self.records.values()]
            self.data_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            path_str = str(self.data_path.resolve())
            self._records_cache[path_str] = (self.data_path.stat().st_mtime, self.records.copy())
        except Exception as e:
            logger.error(f"Failed to save malicious packages to {self.data_path}: {e}")

    def is_malicious_package(self, ecosystem: str, package_name: str, version: str | None = None) -> bool:
        record = self.get_malicious_record(ecosystem, package_name, version)
        return record is not None

    def get_malicious_record(self, ecosystem: str | None, package_name: str | None, version: str | None = None) -> MaliciousPackageRecord | None:
        if not ecosystem or not package_name:
            return None

        key = f"{ecosystem.lower()}::{package_name}"
        record = self.records.get(key)
        if not record:
            return None

        if version is None:
            return record

        # If versions are specified
        if record.affected_versions and version in record.affected_versions:
            return record

        # If ranges are specified
        if record.ranges:
            for r in record.ranges:
                r_type = r.get("type", "SEMVER")
                events = r.get("events", [])
                event_specs = []
                for e in events:
                    event_specs.append(
                        EventSpec(
                            introduced=e.get("introduced"),
                            fixed=e.get("fixed"),
                            last_affected=e.get("last_affected"),
                            limit=e.get("limit")
                        )
                    )

                if event_specs:
                    range_spec = RangeSpec(type=RangeType(r_type), events=tuple(event_specs))
                    if is_version_affected(version, (range_spec,)):
                        return record

        # If no specific versions or ranges are defined, or ranges is universal (0.0.0 to *)
        if not record.affected_versions and not record.ranges:
            return record

        # Check universal range 0.0.0
        if record.ranges:
            for r in record.ranges:
                events = r.get("events", [])
                if len(events) == 1 and events[0].get("introduced") in ("0", "0.0.0"):
                    return record

        return None

    def sync_upstream(self):
        urls = [
            "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
            "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
        ]

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        new_records = 0
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "mcp-vulnerabilities"})
                with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                    if resp.status == 200:
                        zip_data = resp.read()
                        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                            for filename in zf.namelist():
                                if filename.endswith(".json"):
                                    try:
                                        with zf.open(filename) as f:
                                            data = json.load(f)
                                            if data.get("id", "").startswith("MAL-"):
                                                record = OpenSsfMalwareConverter.parse_record(data)
                                                key = f"{record.ecosystem.lower()}::{record.package_name}"
                                                self.records[key] = record
                                                new_records += 1
                                    except Exception as e:
                                        logger.debug(f"Failed to parse OSV record {filename}: {e}")
            except urllib.error.URLError as e:
                logger.warning(f"Failed to sync from {url}: {e}")

        if new_records > 0:
            self.save()
        logger.info(f"Synced {new_records} malicious packages from upstream")

"""EPSS (Exploit Prediction Scoring System) threat intelligence client and models."""

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass
class EpssScore:
    """Represents an EPSS (Exploit Prediction Scoring System) evaluation for a CVE."""

    cve_id: str
    score: float
    percentile: float
    date: str

    @property
    def is_high_risk(self) -> bool:
        """Determines whether the vulnerability meets high EPSS exploitation risk thresholds.

        Returns:
            bool: True if EPSS score >= 0.36 or percentile >= 0.90, False otherwise.
        """
        return self.score >= 0.36 or self.percentile >= 0.90


class EpssClient:
    """Client for querying and caching FIRST.org EPSS scores with rate-limiting and caching."""

    def __init__(self, cache_file: str = "data/epss_cache.json") -> None:
        """Initializes the EPSS client with local cache persistence.

        Args:
            cache_file: File path for local disk cache of EPSS scores.
        """
        self.cache_file = cache_file
        self.base_url = "https://api.first.org/data/v1/epss"
        self._cache: dict[str, Any] = self._load_cache()

    def _load_cache(self) -> dict[str, Any]:
        """Loads cached EPSS scores from disk if available."""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"last_sync_utc": "1970-01-01T00:00:00Z", "scores": {}}

    def _save_cache(self) -> None:
        """Saves current EPSS cache state to disk."""
        os.makedirs(os.path.dirname(self.cache_file) or ".", exist_ok=True)
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f)
        except Exception:
            pass

    def _is_cache_valid(self) -> bool:
        """Checks if the local EPSS cache is within the 24-hour TTL window."""
        last_sync = datetime.fromisoformat(self._cache["last_sync_utc"].replace("Z", "+00:00"))
        # 24 hour TTL
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        return (now - last_sync.replace(tzinfo=None)) < timedelta(hours=24)

    def _update_cache_sync_time(self) -> None:
        """Updates cache synchronization timestamp to current UTC time."""
        self._cache["last_sync_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def get_scores(self, cve_ids: list[str]) -> dict[str, EpssScore]:
        """Retrieves EPSS scores for a list of CVE identifiers, leveraging cache and batch API requests.

        Args:
            cve_ids: List of CVE IDs (e.g. ['CVE-2023-1234', 'CVE-2024-5678']).

        Returns:
            Dictionary mapping CVE ID strings to EpssScore instances.
        """
        if not cve_ids:
            return {}

        results: dict[str, EpssScore] = {}
        cve_ids = list(set(cve_ids))

        # Check cache first for all IDs if it is valid
        # We also fallback to stale cache if offline, but first try fetching if invalid
        cache_valid = self._is_cache_valid()
        missing_ids: list[str] = []
        for cve in cve_ids:
            if cache_valid and cve in self._cache["scores"]:
                data = self._cache["scores"][cve]
                results[cve] = EpssScore(cve, data["score"], data["percentile"], data["date"])
            else:
                missing_ids.append(cve)

        if not missing_ids:
            return results

        # Batch missing IDs by 100
        batch_size = 100
        new_scores: dict[str, dict[str, Any]] = {}
        fetch_success = True

        for i in range(0, len(missing_ids), batch_size):
            batch = missing_ids[i : i + batch_size]
            cve_param = ",".join(batch)
            url = f"{self.base_url}?cve={cve_param}"

            # Rate limiting / Exponential backoff
            retries = 3
            backoff = 1.0
            batch_success = False

            while retries > 0:
                try:
                    # Enforce 10 req/s roughly (0.1s sleep)
                    time.sleep(0.1)

                    req = urllib.request.Request(url, headers={"User-Agent": "mcp-vuln/1.0"})
                    with urllib.request.urlopen(req, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        for item in data.get("data", []):
                            cve = item.get("cve")
                            if cve:
                                epss = float(item.get("epss", 0.0))
                                percentile = float(item.get("percentile", 0.0))
                                date = item.get("date", "")
                                new_scores[cve] = {"score": epss, "percentile": percentile, "date": date}
                        batch_success = True
                        break  # Success
                except urllib.error.HTTPError as e:
                    if e.code == 429:
                        time.sleep(backoff)
                        backoff *= 2
                        retries -= 1
                    else:
                        retries -= 1
                        time.sleep(backoff)
                except Exception:
                    retries -= 1
                    time.sleep(backoff)

            if not batch_success:
                fetch_success = False
                break

        if fetch_success:
            self._cache["scores"].update(new_scores)
            self._update_cache_sync_time()
            self._save_cache()

            for cve, data in new_scores.items():
                results[cve] = EpssScore(cve, data["score"], data["percentile"], data["date"])

        # Fill remaining with stale cache if available
        for cve in missing_ids:
            if cve not in results and cve in self._cache["scores"]:
                data = self._cache["scores"][cve]
                results[cve] = EpssScore(cve, data["score"], data["percentile"], data["date"])

        return results


__all__ = ["EpssScore", "EpssClient"]

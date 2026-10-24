import json
import hashlib
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

class TwoTierVulnerabilityCache:
    """Two-tier disk and memory cache for caching version vulnerability matrices."""

    def __init__(self, cache_dir: Optional[str | Path] = None):
        if cache_dir is None:
            env_dir = os.environ.get("MCP_VULN_CACHE_DIR") or os.environ.get("MCP_CACHE_DIR")
            if env_dir:
                self.cache_dir = Path(env_dir)
            else:
                home = Path(os.environ.get("HOME", str(Path.home())))
                self.cache_dir = home / ".cache" / "mcp-vulnerabilities" / "vuln_matrix"
        else:
            self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._memory_cache: Dict[str, Any] = {}

    def _get_key(self, passport_canonical_hash: str, osv_index_hash: str) -> str:
        """Combine hashes into a single cache key."""
        raw = f"{passport_canonical_hash}:{osv_index_hash}".encode('utf-8')
        return hashlib.sha256(raw).hexdigest()

    def get(self, passport_canonical_hash: str, osv_index_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve precomputed version vulnerability matrix from cache."""
        key = self._get_key(passport_canonical_hash, osv_index_hash)
        
        # Tier 1: In-memory LRU cache
        if key in self._memory_cache:
            return self._memory_cache[key]
        
        # Tier 2: Disk cache
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding='utf-8'))
                self._memory_cache[key] = data
                return data
            except Exception:
                # Corrupt cache, ignore
                pass
        
        return None

    def set(self, passport_canonical_hash: str, osv_index_hash: str, data: Dict[str, Any]) -> None:
        """Save computed version vulnerability matrix to cache."""
        key = self._get_key(passport_canonical_hash, osv_index_hash)
        
        # Tier 1
        self._memory_cache[key] = data
        
        # Tier 2
        cache_file = self.cache_dir / f"{key}.json"
        try:
            cache_file.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
        except Exception:
            pass

    def clear(self) -> None:
        """Clear the cache."""
        self._memory_cache.clear()
        if self.cache_dir.exists():
            for f in self.cache_dir.glob("*.json"):
                try:
                    f.unlink()
                except Exception:
                    pass

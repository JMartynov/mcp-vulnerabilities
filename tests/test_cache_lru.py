import json
import pytest
from pathlib import Path
from mcp_vulnerabilities.cache import TwoTierVulnerabilityCache


def test_two_tier_cache_bounded_lru_eviction(tmp_path: Path):
    """Verify that TwoTierVulnerabilityCache respects maxsize and evicts LRU items."""
    cache = TwoTierVulnerabilityCache(cache_dir=tmp_path / "cache", maxsize=3)
    assert cache.maxsize == 3
    assert len(cache._memory_cache) == 0

    # Insert 3 items (hashA, hashB, hashC)
    cache.set("hashA", "idx1", {"data": "A"})
    cache.set("hashB", "idx1", {"data": "B"})
    cache.set("hashC", "idx1", {"data": "C"})

    assert len(cache._memory_cache) == 3
    keyA = cache._get_key("hashA", "idx1")
    keyB = cache._get_key("hashB", "idx1")
    keyC = cache._get_key("hashC", "idx1")
    assert list(cache._memory_cache.keys()) == [keyA, keyB, keyC]

    # Access hashA via get(), which should move keyA to MRU (end of OrderedDict)
    valA = cache.get("hashA", "idx1")
    assert valA == {"data": "A"}
    assert list(cache._memory_cache.keys()) == [keyB, keyC, keyA]

    # Insert a 4th item (hashD). keyB should be evicted from memory as LRU.
    cache.set("hashD", "idx1", {"data": "D"})
    assert len(cache._memory_cache) == 3
    keyD = cache._get_key("hashD", "idx1")
    assert keyB not in cache._memory_cache
    assert list(cache._memory_cache.keys()) == [keyC, keyA, keyD]

    # However, keyB is still available on disk (Tier 2).
    # When fetched, it should be reloaded into memory cache and trigger LRU eviction of keyC.
    valB = cache.get("hashB", "idx1")
    assert valB == {"data": "B"}
    assert len(cache._memory_cache) == 3
    assert keyC not in cache._memory_cache
    assert list(cache._memory_cache.keys()) == [keyA, keyD, keyB]


def test_two_tier_cache_clear(tmp_path: Path):
    """Verify that clear() empties both memory LRU and disk cache."""
    cache = TwoTierVulnerabilityCache(cache_dir=tmp_path / "cache", maxsize=2)
    cache.set("h1", "i1", {"val": 1})
    cache.set("h2", "i2", {"val": 2})

    assert len(cache._memory_cache) == 2
    assert len(list((tmp_path / "cache").glob("*.json"))) == 2

    cache.clear()
    assert len(cache._memory_cache) == 0
    assert len(list((tmp_path / "cache").glob("*.json"))) == 0
    assert cache.get("h1", "i1") is None

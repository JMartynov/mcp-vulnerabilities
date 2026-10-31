import pytest
import json
from pathlib import Path

def test_service_worker_caches_updates_and_shards():
    with open("docs/sw.js", "r", encoding="utf-8") as f:
        js = f.read()
    assert "updates/" in js or "updates.json" in js, "sw.js must contain a caching rule for updates"
    assert "shards/" in js, "sw.js must cache catalog shards"

def test_manifest_pwa_spec_compliance():
    with open("docs/manifest.json", "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest.get("display") == "standalone"
    assert manifest.get("start_url") is not None
    assert len(manifest.get("icons", [])) > 0

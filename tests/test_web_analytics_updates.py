import pytest
from pathlib import Path

def test_analytics_drilldowns_use_url_encoding():
    with open("docs/analytics.js", "r", encoding="utf-8") as f:
        js = f.read()
    assert "encodeURIComponent" in js, "Drilldown links must encode query parameters"

def test_updates_uses_numeric_semver_sorting():
    with open("docs/updates.js", "r", encoding="utf-8") as f:
        js = f.read()
    assert "split('.')" in js or "localeCompare" in js, "Must parse version numbers for sorting"

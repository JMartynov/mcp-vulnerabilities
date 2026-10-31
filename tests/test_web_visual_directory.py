import pytest
from pathlib import Path

def test_sentinel_element_exists_in_index():
    with open("docs/index.html", "r", encoding="utf-8") as f:
        html = f.read()
    assert 'id="scroll-sentinel"' in html or 'class="scroll-sentinel"' in html

def test_app_js_implements_intersection_observer():
    with open("docs/app.js", "r", encoding="utf-8") as f:
        js = f.read()
    assert "IntersectionObserver" in js, "app.js must implement IntersectionObserver for infinite scrolling"
    assert "slice(0, 100)" not in js, "app.js must not hard-truncate cards at 100 items"

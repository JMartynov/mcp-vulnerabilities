import subprocess
import shutil
from pathlib import Path
import pytest


def test_index_html_structure():
    content = Path("docs/index.html").read_text(encoding="utf-8")
    assert 'id="config-audit-zone"' in content
    assert "primitives-tabs-nav" in content
    assert "aria-label" in content


def test_updates_html_structure():
    content = Path("docs/updates.html").read_text(encoding="utf-8")
    assert 'id="historical-sparkline"' in content
    assert 'id="change-type-filters"' in content
    assert "data/feed.atom" in content
    assert "data/feed.json" in content


def test_analytics_html_structure():
    content = Path("docs/analytics.html").read_text(encoding="utf-8")
    assert 'id="chart-zero-day"' in content
    assert "Zero-Day & Remediation Gap" in content
    assert 'id="chart-capabilities"' in content
    assert "Static Capability & Permission Surface" in content
    assert 'id="chart-secrets"' in content
    assert "Secrets Perimeter" in content
    assert 'id="chart-shadowing"' in content
    assert "Tool Shadowing Risk" in content


def test_js_syntax():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js not installed, skipping JS syntax check")
    
    subprocess.run([node, "-c", "docs/app.js"], check=True)
    subprocess.run([node, "-c", "docs/updates.js"], check=True)

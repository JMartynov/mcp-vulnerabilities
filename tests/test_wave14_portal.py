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


def test_wave15_frontend_remediations():
    app_js = Path("docs/app.js").read_text(encoding="utf-8")
    # Task 78: applyAdvisoryFilters must use advisoryHasVulnerableTools and never reference server.tools_count
    assert "function advisoryHasVulnerableTools(" in app_js
    adv_filter_start = app_js.index("function applyAdvisoryFilters()")
    adv_filter_body = app_js[adv_filter_start:adv_filter_start + 1500]
    assert "server.tools_count" not in adv_filter_body
    assert "advisoryHasVulnerableTools(adv)" in adv_filter_body

    # Task 79: composite_risk_tier consumed in getServerCompositeRisk
    assert "server.composite_risk_tier" in app_js

    # Task 80: CVE/GHSA & CVSS posture rendering in Config Auditor
    assert "findMatchingAdvisoriesForPackage" in app_js
    assert "audit-cve-list" in app_js

def test_wave15_css_and_html_hygiene():
    # Task 82 CSS
    css_content = Path("docs/style.css").read_text(encoding="utf-8")
    assert "--bg-tertiary" in css_content
    assert "--primary-color" in css_content
    assert "--bg-card" in css_content
    assert "--bg-hover" in css_content
    assert "--badge-bg" in css_content
    assert ".badge-eco" in css_content

    # Task 82 HTML Updates
    updates_html = Path("docs/updates.html").read_text(encoding="utf-8")
    import re
    # Check that all target="_blank" links have rel="noopener"
    blank_links = re.findall(r'<a[^>]+target=["\']_blank["\'][^>]*>', updates_html, re.IGNORECASE)
    for link in blank_links:
        assert 'rel="noopener"' in link or "rel='noopener'" in link

    # Check SVG viewBox
    assert 'viewBox="0 0 1000 80"' in updates_html
    assert '<svg id="historical-sparkline"' in updates_html

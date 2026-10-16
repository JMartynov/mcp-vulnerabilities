"""Tests for the unified web portal UI (docs/index.html, docs/app.js, docs/style.css)."""

from pathlib import Path
import re


def test_index_html_structure():
    index_file = Path("docs/index.html")
    assert index_file.exists(), "docs/index.html must exist"
    content = index_file.read_text(encoding="utf-8")

    # 1. Top navigation link to updates.html
    assert 'href="updates.html"' in content or "updates.html" in content, "Missing link to updates.html"

    # 2. Dual-tab navigation (Directory & Advisories)
    assert 'data-tab="directory"' in content, "Missing directory tab"
    assert 'data-tab="advisories"' in content, "Missing advisories tab"
    assert 'id="directory-view"' in content, "Missing directory view container"
    assert 'id="advisories-view"' in content, "Missing advisories view container"

    # 3. Server cards container
    assert 'id="servers-container"' in content, "Missing servers container"

    # 4. Server inspector modal with version selector & parameter tables
    assert 'id="server-modal"' in content, "Missing server inspector modal"
    assert 'id="modal-version-pills"' in content, "Missing version selector pills container"
    assert 'id="selected-version-vuln-container"' in content, "Missing version vulnerability matrix container"
    assert 'id="modal-tools-container"' in content, "Missing tools and parameters container"
    assert 'id="modal-security-comment"' in content, "Missing security comment container"
    assert 'id="modal-server-repo"' in content, "Missing source repo link container"

    # 5. Safe client config exporters
    assert 'data-client="claude"' in content, "Missing Claude config export button"
    assert 'data-client="cursor"' in content, "Missing Cursor config export button"
    assert 'data-client="cline"' in content, "Missing Cline config export button"
    assert 'data-client="zed"' in content, "Missing Zed config export button"


def test_app_js_functionality():
    app_file = Path("docs/app.js")
    assert app_file.exists(), "docs/app.js must exist"
    content = app_file.read_text(encoding="utf-8")

    # 1. Loads mcp_catalog_index.json and on-demand shards
    assert "data/mcp_catalog_index.json" in content, "app.js must fetch mcp_catalog_index.json"
    assert re.search(r"data/shards/\$\{?shard", content) or "data/shards/" in content, "app.js must fetch on-demand shards"

    # 2. Dual-tab switching
    assert "switchTab" in content or "tabDirectory" in content, "Missing tab switching logic"

    # 3. Interactive version selector
    assert "version-pill" in content, "Missing version pill selector in app.js"
    assert "selectVersion" in content, "Missing selectVersion logic in app.js"

    # 4. Version-separated vulnerability matrix
    assert "version-vuln-matrix" in content or "selectedVersionVulnContainer" in content, "Missing version vulnerability matrix"

    # 5. Parameter schema table columns: Name, Type, Required, Default, Enum, Description
    for col in ["Name", "Type", "Required", "Default", "Enum", "Description"]:
        assert f"<th>{col}</th>" in content, f"Missing parameter schema column header: {col}"

    # 6. Tool security comment rendering
    assert "tool.security_comment" in content or "tool-security-comment" in content, "Missing tool security comment rendering"

    # 7. Safe client config exporters for AI clients
    assert "exportConfig" in content, "Missing exportConfig function"
    assert "mcpServers" in content, "Missing mcpServers config payload generation"
    assert "claude" in content and "cursor" in content and "cline" in content and "zed" in content, "Missing multi-client config generation"


def test_style_css_rules():
    css_file = Path("docs/style.css")
    assert css_file.exists(), "docs/style.css must exist"
    content = css_file.read_text(encoding="utf-8")

    # Check key UI classes
    assert ".portal-tabs" in content
    assert ".portal-tab" in content
    assert ".servers-grid" in content
    assert ".server-card" in content
    assert ".version-pill" in content
    assert ".params-table" in content
    assert ".btn-export" in content

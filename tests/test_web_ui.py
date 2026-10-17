"""Tests for the Security Explorer Version Switcher and Remediation UI (Task 49)."""

from pathlib import Path
import re

def test_index_html_remediation_structure():
    index_file = Path("docs/index.html")
    assert index_file.exists(), "docs/index.html must exist"
    content = index_file.read_text(encoding="utf-8")

    # Verify structural containers exist
    assert 'id="server-modal"' in content, "Missing server inspector modal"
    assert 'id="modal-version-pills"' in content, "Missing version selector pills container"
    assert 'id="selected-version-vuln-container"' in content, "Missing version vulnerability matrix container"

def test_app_js_remediation_logic():
    app_file = Path("docs/app.js")
    assert app_file.exists(), "docs/app.js must exist"
    content = app_file.read_text(encoding="utf-8")

    # Version switching logic
    assert "function selectVersion" in content, "Missing selectVersion logic"
    assert "currentInspectedVersion" in content, "Missing state tracking for inspected version"
    
    # URL Deep linking logic
    assert "URLSearchParams" in content or "URL(" in content, "Missing URL parameter deep-linking"
    assert "searchParams.set" in content, "Missing logic to set URL params"
    assert "window.history.replaceState" in content, "Missing logic to replace history state for deep-linking"
    
    # Remediation logic
    assert "remediation-box" in content, "Missing remediation box class"
    assert "remediation-command-wrap" in content, "Missing remediation command container"
    assert "btn-copy-cmd" in content, "Missing copy command button"
    assert "navigator.clipboard.writeText" in content, "Missing clipboard copy logic"

    # Upstream check
    assert "No fixed version available upstream yet" in content, "Missing fallback remediation messaging"

def test_style_css_remediation():
    css_file = Path("docs/style.css")
    assert css_file.exists(), "docs/style.css must exist"
    content = css_file.read_text(encoding="utf-8")

    # Remediation classes
    assert ".remediation-box" in content, "Missing remediation box styling"
    assert ".remediation-command-wrap" in content, "Missing remediation command wrap styling"
    assert ".btn-copy-cmd" in content, "Missing copy command button styling"


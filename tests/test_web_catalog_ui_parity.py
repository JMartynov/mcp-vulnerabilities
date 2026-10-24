"""Tests for Web Security Explorer UI Parity: Tool Expansion, Zero-Tool States, and Multi-Facet Filters."""

from pathlib import Path
import re

def test_index_html_ui_parity_elements():
    index_file = Path("docs/index.html")
    assert index_file.exists()
    content = index_file.read_text(encoding="utf-8")
    
    assert 'id="filterToolsOnly"' in content, "Missing #filterToolsOnly checkbox in docs/index.html"
    assert 'Has Tools Only' in content, "Missing 'Has Tools Only' label in docs/index.html"
    assert 'class="filter-checkbox"' in content, "Missing filter-checkbox class in docs/index.html"

def test_updates_html_ui_parity_elements():
    updates_file = Path("docs/updates.html")
    assert updates_file.exists()
    content = updates_file.read_text(encoding="utf-8")
    
    assert 'id="filterToolsOnly"' in content, "Missing #filterToolsOnly checkbox in docs/updates.html"
    assert 'Has Tools Only' in content, "Missing 'Has Tools Only' label in docs/updates.html"
    assert 'class="filter-checkbox"' in content, "Missing filter-checkbox class in docs/updates.html"

def test_style_css_ui_parity():
    css_file = Path("docs/style.css")
    assert css_file.exists()
    content = css_file.read_text(encoding="utf-8")
    
    assert '.tool-more' in content or '.tool-tag-more' in content, "Missing expansion tag styles"
    assert '.no-tools-badge' in content, "Missing .no-tools-badge styles"
    assert '.filter-checkbox' in content, "Missing .filter-checkbox styles"
    assert 'cursor: pointer' in content and ('.tool-pill' in content or '.tool-tag' in content), "Missing cursor pointer for tool tags"
    assert '.tool-more:focus' in content or '.tool-tag-more:focus' in content, "Missing focus state for accessibility"
    assert '.tool-more:hover' in content or '.tool-tag-more:hover' in content, "Missing hover state"

def test_app_js_tool_expansion_and_zero_state():
    js_file = Path("docs/app.js")
    assert js_file.exists()
    content = js_file.read_text(encoding="utf-8")
    
    # 1. State Tracking
    assert 'let expandedToolServers = new Set()' in content, "Missing expanded tool servers tracking in app.js"
    assert 'window.toggleToolsExpand' in content, "Missing global toggleToolsExpand function"
    
    # 2. Zero-tool state invariant
    assert 'no-tools-badge' in content, "Missing zero-tool rendering logic"
    assert 'No static tools declared' in content, "Missing text for zero tools badge"
    
    # 3. Tool expansion invariant
    assert 'Math.min(5, allTools.length)' in content or 'Math.min(5,' in content, "Missing slice logic for expanded tools"
    assert 'role="button"' in content, "Missing accessibility role for expansion button"
    assert 'tabindex="0"' in content, "Missing accessibility tabindex for expansion button"
    assert 'onkeypress' in content and 'Enter' in content, "Missing keyboard accessibility on tool expansion tag"
    
    # 4. Filter Tools Only invariant
    assert 'el.filterToolsOnly && el.filterToolsOnly.checked' in content, "Missing filterToolsOnly logic in app.js"

def test_updates_js_tool_expansion_and_zero_state():
    js_file = Path("docs/updates.js")
    assert js_file.exists()
    content = js_file.read_text(encoding="utf-8")
    
    # 1. State Tracking
    assert 'let expandedToolServers = new Set()' in content, "Missing expanded tool servers tracking in updates.js"
    assert 'window.toggleToolsExpand' in content, "Missing global toggleToolsExpand function"
    
    # 2. Zero-tool state invariant
    assert 'no-tools-badge' in content, "Missing zero-tool rendering logic"
    assert 'No static tools declared' in content, "Missing text for zero tools badge"
    
    # 3. Tool expansion invariant
    assert 'Math.min(5, tools.length)' in content or 'Math.min(5,' in content, "Missing slice logic for expanded tools"
    assert 'role="button"' in content, "Missing accessibility role for expansion button"
    assert 'tabindex="0"' in content, "Missing accessibility tabindex for expansion button"
    
    # 4. Filter Tools Only invariant
    assert 'el.filterToolsOnly && el.filterToolsOnly.checked' in content, "Missing filterToolsOnly logic in updates.js"

def test_inspector_modal_linkage():
    app_js_content = Path("docs/app.js").read_text(encoding="utf-8")
    updates_js_content = Path("docs/updates.js").read_text(encoding="utf-8")
    
    # Open Inspector Function Bound
    assert 'window.openInspectorModal' in app_js_content, "Missing openInspectorModal in app.js"
    assert 'window.openInspectorModal' in updates_js_content, "Missing openInspectorModal in updates.js"
    
    # Invariant 4A: Opens inspector modal, scrolls to highlighted element
    assert '.scrollIntoView' in app_js_content, "Inspector modal linkage missing smooth scroll to tool in app.js"
    assert '.scrollIntoView' in updates_js_content, "Inspector modal linkage missing smooth scroll to tool in updates.js"
    
    # Ensure tool tags have click handler calling openInspectorModal
    assert "onclick=\"openInspectorModal" in app_js_content or "onclick='openInspectorModal" in app_js_content, "Missing onclick handler for tool pills in app.js"
    assert "onclick=\"openInspectorModal" in updates_js_content or "onclick='openInspectorModal" in updates_js_content, "Missing onclick handler for tool pills in updates.js"

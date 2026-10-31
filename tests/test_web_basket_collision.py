import pytest
from pathlib import Path

def test_basket_drawer_elements_exist_in_index():
    with open("docs/index.html", "r", encoding="utf-8") as f:
        html = f.read()
    assert 'id="config-basket-drawer"' in html or 'id="configBasketDrawer"' in html
    assert 'id="collisionWarning"' in html

def test_collision_warning_scope_integrity():
    with open("docs/app.js", "r", encoding="utf-8") as f:
        js = f.read()
    # selectedServers must be declared before use
    assert "let selectedServers = new Set()" in js or "const selectedServers" in js, "selectedServers must be declared in app.js"
    # Ensure detectCollisions does not crash on unbound variable
    assert "function detectCollisions" in js or "window.detectCollisions" in js

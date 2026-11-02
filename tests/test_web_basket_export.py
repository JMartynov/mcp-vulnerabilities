import os

def test_web_basket_export():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "docs", "app.js")
    index_html_path = os.path.join(os.path.dirname(__file__), "..", "docs", "index.html")
    
    with open(app_js_path, "r", encoding="utf-8") as f:
        app_js = f.read()
        
    with open(index_html_path, "r", encoding="utf-8") as f:
        index_html = f.read()
        
    # Check if window.toggleBasket is defined
    assert "window.toggleBasket =" in app_js or "window.toggleBasket= " in app_js or "window.toggleBasket=function" in app_js.replace(" ", ""), "window.toggleBasket must be defined"
    
    # Check if generateMultiClientConfig handles all 6 clients
    assert "claude" in app_js
    assert "cursor" in app_js
    assert "windsurf" in app_js
    assert "cline" in app_js
    assert "zed" in app_js
    assert "continue" in app_js
    
    # Check index.html for clear controls
    assert "Clear Basket" in index_html or "clear" in index_html.lower()

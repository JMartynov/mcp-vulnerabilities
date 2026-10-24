import pytest
import subprocess
import time
import os
import json
import socket

playwright_sync = pytest.importorskip("playwright.sync_api")
sync_playwright = playwright_sync.sync_playwright

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 0))
    port = s.getsockname()[1]
    s.close()
    return port

@pytest.fixture(scope="session")
def server():
    port = get_free_port()
    proc = subprocess.Popen(["python3", "-m", "http.server", str(port)], cwd="docs")
    time.sleep(2)
    yield f"http://localhost:{port}"
    proc.terminate()
    proc.wait()

def test_all_scenarios(server):
    synthetic_index = [
        {
            "package_name": "zero-tools-vuln",
            "display_name": "Zero Tools Vuln Server",
            "ecosystem": "npm",
            "is_vulnerable": True,
            "highest_risk_tier": "HIGH",
            "tools_count": 0,
            "shard_file": "zero_tools.json"
        },
        {
            "package_name": "has-tools-safe",
            "display_name": "Has Tools Safe Server",
            "ecosystem": "python",
            "is_vulnerable": False,
            "highest_risk_tier": "LOW",
            "tools_count": 5,
            "shard_file": "has_tools.json"
        },
        {
            "package_name": "<img src=x onerror=alert(1)>",
            "display_name": "XSS Package",
            "description": "<svg onload=alert(1)>",
            "ecosystem": "npm",
            "is_vulnerable": False,
            "highest_risk_tier": "LOW",
            "tools_count": 1,
            "shard_file": "xss_package.json"
        }
    ]
    
    xss_shard = {
        "<img src=x onerror=alert(1)>": {
            "package_name": "<img src=x onerror=alert(1)>",
            "display_name": "XSS Package",
            "description": "<svg onload=alert(1)>",
            "versions": [
                {
                    "version": "1.0.0",
                    "tools": [
                        {
                            "name": "javascript:alert(1)",
                            "description": "<img src=x onerror=alert(1)>"
                        }
                    ]
                }
            ]
        }
    }

    zero_tools_shard = {
        "zero-tools-vuln": {
            "package_name": "zero-tools-vuln",
            "display_name": "Zero Tools Vuln Server",
            "versions": [
                {
                    "version": "1.0.0",
                    "tools": []
                }
            ]
        }
    }

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:
            pytest.skip(f"Playwright chromium browser not available: {e}")
        page = browser.new_page()
        
        # Intercept network requests for the synthetic data
        def intercept_data(route, request):
            if "data/mcp_catalog_index.json" in request.url:
                route.fulfill(json=synthetic_index)
            elif "data/shards/xss_package.json" in request.url:
                route.fulfill(json=xss_shard)
            elif "data/shards/zero_tools.json" in request.url:
                route.fulfill(json=zero_tools_shard)
            elif "data/shards/" in request.url:
                route.abort("failed")
            else:
                route.continue_()
                
        page.route("**/*", intercept_data)

        alert_triggered = False
        def handle_dialog(dialog):
            nonlocal alert_triggered
            alert_triggered = True
            dialog.dismiss()
        page.on("dialog", handle_dialog)
        
        # Test 1A & 1B: Filter Logic
        page.goto(f"{server}/index.html")
        page.wait_for_selector(".server-card")
        
        page.fill("#directory-search-input", "Zero Tools Vuln Server")
        page.wait_for_timeout(500)
        assert page.locator(".server-title:has-text('Zero Tools Vuln Server')").is_visible()
        
        zero_tools_card = page.locator(".server-card", has=page.locator(".server-title:has-text('Zero Tools Vuln Server')"))
        assert zero_tools_card.locator(".no-tools-badge").is_visible()
        
        page.check("#filterToolsOnly")
        page.wait_for_timeout(500)
        assert not page.locator(".server-title:has-text('Zero Tools Vuln Server')").is_visible()
        page.uncheck("#filterToolsOnly")
        
        # Test 2A: DOM XSS Immunity
        page.fill("#directory-search-input", "")
        page.wait_for_timeout(500)
        
        # Wait to ensure no alerts
        page.wait_for_timeout(1000)
        assert not alert_triggered, "XSS was triggered on index render!"
        
        # Click the XSS card
        inspect_btn = page.locator(".server-card", has=page.locator(".server-pkg-name", has_text="<img src=x onerror=alert(1)>")).locator(".btn-inspect")
        inspect_btn.click()
        page.wait_for_selector("#server-modal", state="visible")
        
        # Wait for shard load
        page.wait_for_timeout(1000)
        assert not alert_triggered, "XSS was triggered on shard render!"
        
        page.locator("#server-modal-close").click()
        
        # Test 2B: Query route XSS
        page.goto(f"{server}/index.html?server=<img src=x onerror=alert(1)>")
        page.wait_for_timeout(1000)
        assert not alert_triggered, "XSS was triggered via query hash route!"
        
        # Test 3B: Shard fetch failure
        # Go back to index and click something that will fail to load (has-tools-safe shard isn't mocked so it will fail per the route logic)
        page.goto(f"{server}/index.html")
        page.wait_for_selector(".server-card")
        
        page.fill("#directory-search-input", "Has Tools Safe Server")
        page.wait_for_timeout(500)
        
        inspect_btn = page.locator(".server-card", has=page.locator(".server-title:has-text('Has Tools Safe Server')")).locator(".btn-inspect")
        inspect_btn.click()
        page.wait_for_selector("#server-modal", state="visible")
        
        error_msg = page.locator("#modal-version-pills .error-msg")
        error_msg.wait_for(state="visible", timeout=5000)
        assert error_msg.is_visible()
        assert page.locator("#modal-version-pills button:has-text('Retry Fetch')").is_visible()
        
        browser.close()

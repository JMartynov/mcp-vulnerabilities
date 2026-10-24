import pytest
import subprocess
import time
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

def test_task80_cve_rendering(server):
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:
            pytest.skip(f"Playwright chromium browser not available: {e}")
        page = browser.new_page()
        
        # intercept and return synthetic advisories
        all_advisories = [{
            "id": "CVE-2024-9999",
            "summary": "Synthetic CVE for Task 80",
            "database_specific": {
                "severity": "CRITICAL",
                "cvss_score": 9.8
            },
            "affected": [
                {
                    "package": {
                        "name": "@modelcontextprotocol/server-filesystem"
                    }
                }
            ]
        }]
        
        catalog_index = [{
            "package_name": "@modelcontextprotocol/server-filesystem",
            "display_name": "FS Server",
            "ecosystem": "npm",
            "is_vulnerable": True,
            "recommended_safe_version": "1.2.3",
            "highest_risk_tier": "CRITICAL"
        }]

        def intercept_data(route, request):
            if "data/vulnerabilities.json" in request.url:
                route.fulfill(json=all_advisories)
            elif "data/mcp_catalog_index.json" in request.url:
                route.fulfill(json=catalog_index)
            elif "data/shards/" in request.url:
                route.abort("failed")
            else:
                route.continue_()
                
        page.route("**/*", intercept_data)

        page.goto(f"{server}/index.html")
        page.wait_for_selector(".server-card") # wait for initial load

        page.locator("#tab-audit").click()
        page.wait_for_selector("#audit-file-input", state="attached")
        
        # provide a text payload
        config_payload = '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"]}}}'
        
        # Since handleAuditText is defined inside the IIFE, we can trigger audit via file input or textarea or expose it if needed.
        # Let's check how audit input is handled: el.auditFileInput change or textarea input / drop
        page.evaluate(f"""() => {{
            const textarea = document.getElementById("config-audit-textarea");
            if (textarea) {{
                textarea.value = '{config_payload}';
                textarea.dispatchEvent(new Event('input', {{ bubbles: true }}));
            }}
        }}""")

        # Wait for audit results container
        page.wait_for_selector("#audit-results-container", state="visible")
        
        # Verify rendered items
        assert page.locator(".audit-cve-list").is_visible(), "audit-cve-list should be visible"
        cve_item = page.locator(".audit-cve-item")
        assert cve_item.is_visible()
        
        assert "CVE-2024-9999" in cve_item.inner_text()
        assert "CRITICAL • CVSS 9.8" in cve_item.inner_text()
        assert "Synthetic CVE for Task 80" in cve_item.inner_text()

        # Try a safe version payload
        config_payload_safe = '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3"]}}}'
        page.evaluate(f"""() => {{
            const textarea = document.getElementById("config-audit-textarea");
            if (textarea) {{
                textarea.value = '{config_payload_safe}';
                textarea.dispatchEvent(new Event('input', {{ bubbles: true }}));
            }}
        }}""")
        
        page.wait_for_timeout(500)
        
        # Should be clean
        assert page.locator(".audit-server-item.clean").is_visible()
        assert not page.locator(".audit-server-item.vulnerable").is_visible()
        
        browser.close()

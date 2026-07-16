import os
import uuid
import hashlib
import sys
import asyncio
import subprocess
from playwright.sync_api import sync_playwright

_PLAYWRIGHT_INSTALLED = False

def _ensure_playwright_browsers():
    """Automatically installs Chromium binaries on Streamlit Cloud if missing."""
    global _PLAYWRIGHT_INSTALLED
    if not _PLAYWRIGHT_INSTALLED:
        try:
            subprocess.run(["playwright", "install", "chromium"], check=True, capture_output=True)
        except Exception as e:
            print(f"Warning: Failed to auto-install Playwright browsers: {e}")
        _PLAYWRIGHT_INSTALLED = True

def capture_page(url: str, save_dir: str = "data/evidence") -> dict:
    """
    Use Playwright to navigate to the URL, capture a full-page screenshot, 
    extract the raw HTML, and compute a structural DOM hash.
    Returns paths to saved files and the computed hashes.
    """
    os.makedirs(save_dir, exist_ok=True)
    run_id = str(uuid.uuid4())
    img_path = os.path.join(save_dir, f"{run_id}.png")
    html_path = os.path.join(save_dir, f"{run_id}.html")
    
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    else:
        # If on Linux (Streamlit Cloud), ensure browser binaries exist
        _ensure_playwright_browsers()
    
    with sync_playwright() as p:
        # Added --no-sandbox and --disable-dev-shm-usage for Streamlit Cloud compatibility
        browser = p.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
        )
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        
        # --- SSRF Guard Interceptor ---
        def block_internal(route):
            request = route.request
            req_url = request.url
            import urllib.parse
            hostname = urllib.parse.urlparse(req_url).hostname
            
            if not hostname:
                print(f"Playwright SSRF Blocked: {req_url} (No valid hostname)")
                route.abort("accessdenied")
                return

            try:
                from security.ssrf_guard import resolve_host, is_private_ip, SSRFError
                # Resolve host on every request to prevent DNS rebinding attacks
                ips = resolve_host(req_url)
                for ip in ips:
                    if is_private_ip(ip):
                        raise SSRFError(f"Blocked IP: {ip}")
            except Exception as e:
                print(f"Playwright SSRF Blocked: {req_url} ({e})")
                route.abort("accessdenied")
                return
                
            route.continue_()
            
        page.route("**/*", block_internal)
        # ------------------------------
        
        try:
            # We use networkidle to ensure the page has loaded dynamic content
            page.goto(url, wait_until="networkidle", timeout=15000)
        except Exception as e:
            # Fallback to load state if networkidle times out (e.g. infinite polling on page)
            try:
                page.goto(url, wait_until="load", timeout=10000)
            except Exception as e2:
                print(f"Warning: Playwright capture timed out or failed for {url}: {e2}")

        # Capture screenshot
        page.screenshot(path=img_path, full_page=True)
        
        # Save raw HTML
        html_content = page.content()
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        # Extract structural DOM hash using JavaScript to strip text
        # This gives us a fingerprint of the UI skeleton without the content
        try:
            tag_structure = page.evaluate('''() => {
                const getTags = (el) => {
                    if (!el) return "";
                    let tags = "<" + el.tagName.toLowerCase() + ">";
                    for (let child of el.children) {
                        tags += getTags(child);
                    }
                    tags += "</" + el.tagName.toLowerCase() + ">";
                    return tags;
                };
                return getTags(document.body);
            }''')
        except Exception:
            tag_structure = "<body></body>"
            
        dom_hash = hashlib.sha256(tag_structure.encode("utf-8")).hexdigest()
        
        browser.close()
        
    return {
        "screenshot_path": img_path,
        "html_path": html_path,
        "dom_fingerprint": dom_hash,
        "raw_html": html_content
    }

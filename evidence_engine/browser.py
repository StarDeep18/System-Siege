import os
import uuid
import hashlib
from playwright.sync_api import sync_playwright

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
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        
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

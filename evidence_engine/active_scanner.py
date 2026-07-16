"""
evidence_engine/active_scanner.py — Active Penetration Testing Module.

Executes active payloads against the target to detect SQLi, XSS, sensitive files,
and rate limiting presence.
"""

import requests
import time
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from .models import ActiveScanEvidence


def check_sqli(url: str) -> bool:
    """Inject basic SQL payloads to detect untrapped database errors."""
    payloads = ["'", "' OR '1'='1", "'; DROP TABLE users;--"]
    
    # Try appending to URL
    for payload in payloads:
        try:
            # We add a dummy query param to test reflection
            test_url = f"{url}?id={payload}" if "?" not in url else f"{url}&id={payload}"
            response = requests.get(test_url, timeout=5, verify=False)
            content = response.text.lower()
            
            # Look for common DB error signatures
            db_errors = ["syntax error", "mysql_fetch_array", "ora-", "postgresql query failed", "sql syntax"]
            for err in db_errors:
                if err in content:
                    return True
        except requests.RequestException:
            continue
            
    return False


def check_xss(url: str) -> bool:
    """Inject script payloads to detect reflection without sanitization."""
    payload = "<script>alert('XSS')</script>"
    
    try:
        test_url = f"{url}?q={payload}" if "?" not in url else f"{url}&q={payload}"
        response = requests.get(test_url, timeout=5, verify=False)
        
        # If the exact payload is reflected in the HTML, it's highly likely XSS
        if payload in response.text:
            return True
    except requests.RequestException:
        pass
        
    return False


def check_sensitive_files(url: str) -> list[str]:
    """Perform directory fuzzing for common sensitive files."""
    exposed = []
    # Ensure URL ends without slash for clean joining
    base = url.rstrip('/')
    
    common_files = [
        "/.env",
        "/.git/config",
        "/.DS_Store",
        "/docker-compose.yml",
        "/backup.zip",
        "/config.php"
    ]
    
    for file in common_files:
        try:
            target = base + file
            # Quick HEAD request first
            resp = requests.head(target, timeout=3, verify=False, allow_redirects=False)
            if resp.status_code == 200:
                # Confirm it actually has content (not a 200 soft-404)
                get_resp = requests.get(target, timeout=3, verify=False)
                # Ensure it's not returning HTML (common for soft 404s)
                if get_resp.status_code == 200 and "text/html" not in get_resp.headers.get("Content-Type", ""):
                    exposed.append(file)
        except requests.RequestException:
            continue
            
    return exposed


def check_rate_limiting(url: str) -> bool:
    """
    Send a small burst of requests to see if the server responds with 429 Too Many Requests
    or delays responses. We keep this lightweight (10 requests) to avoid actual DoS.
    """
    try:
        # We'll send 10 concurrent requests
        def fetch():
            return requests.get(url, timeout=3, verify=False).status_code

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(fetch) for _ in range(10)]
            
        results = [f.result() for f in futures]
        
        # If any request was rate limited (429) or forbidden (403 WAF block)
        if 429 in results or 403 in results:
            return True
            
        # If everything succeeded with 200, rate limiting might be missing or threshold is higher
        return False
        
    except Exception:
        # If the server completely dropped the connection on the burst, it's a form of defense
        return True


def run_active_scan(url: str) -> ActiveScanEvidence:
    """Orchestrate all active checks and return evidence."""
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    sqli = check_sqli(url)
    xss = check_xss(url)
    sensitive_files = check_sensitive_files(url)
    rate_limiting = check_rate_limiting(url)
    
    return ActiveScanEvidence(
        sqli_detected=sqli,
        xss_detected=xss,
        sensitive_files_exposed=sensitive_files,
        rate_limiting_active=rate_limiting
    )
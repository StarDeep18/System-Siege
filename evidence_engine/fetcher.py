"""
evidence_engine/fetcher.py — Deterministic website fetching.

Fetches the target URL after the Security Validation Layer has cleared it.
Respects SSRF constraints by connecting directly to the validated IP address
and preserving SNI (Server Name Indication) via a thread-safe DNS override.

Returns raw HTTP data (FetchResult) or an EvidenceError on failure.
"""

from __future__ import annotations

import socket
import threading
import time
from urllib.parse import urlparse, urljoin
from typing import Union, Dict

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pydantic import BaseModel

from evidence_engine.models import EvidenceError
from security.ssrf_guard import check as ssrf_check
from security.ssrf_guard import SSRFError

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ── Configuration ─────────────────────────────────────────────────────────────

REQUEST_TIMEOUT_SECONDS = 15
MAX_RESPONSE_BYTES = 5 * 1024 * 1024   # 5 MB hard cap
MAX_REDIRECTS = 5

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Connection": "keep-alive"
}

# ── Thread-Safe DNS Override for SSRF & SNI Support ───────────────────────────

_dns_overrides = threading.local()
_orig_getaddrinfo = socket.getaddrinfo

def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """
    Returns the pre-resolved safe IP address for a host if it exists in the 
    thread-local overrides map, completely bypassing native DNS for that host.
    """
    overrides = getattr(_dns_overrides, "map", {})
    if host in overrides:
        ip = overrides[host]
        # Return format expected by socket.getaddrinfo: (family, type, proto, canonname, sockaddr)
        if ":" in ip:
            return [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port, 0, 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]
    
    return _orig_getaddrinfo(host, port, family, type, proto, flags)

# Apply global patch exactly once
if not getattr(socket, "_ssrf_patched", False):
    socket.getaddrinfo = _patched_getaddrinfo
    socket._ssrf_patched = True

class ThreadSafeDNSOverride:
    """Context manager to scope the DNS override to the current thread."""
    def __init__(self, host: str, ip: str):
        self.host = host
        self.ip = ip
        self.old_ip = None

    def __enter__(self):
        if not hasattr(_dns_overrides, "map"):
            _dns_overrides.map = {}
        self.old_ip = _dns_overrides.map.get(self.host)
        _dns_overrides.map[self.host] = self.ip

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(_dns_overrides, "map"):
            if self.old_ip is not None:
                _dns_overrides.map[self.host] = self.old_ip
            else:
                _dns_overrides.map.pop(self.host, None)


# ── Data Structures ───────────────────────────────────────────────────────────

class FetchResult(BaseModel):
    """
    Raw HTTP evidence collected from a single website fetch.
    This internal model is passed to Snapshot, Headers, and SSL modules.
    """
    success: bool = True
    url: str
    hostname: str
    resolved_ip: str
    status_code: int
    response_time: float
    headers: Dict[str, str]
    html_content: str


# ── Public Interface ──────────────────────────────────────────────────────────

def fetch(url: str) -> Union[FetchResult, EvidenceError]:
    """
    Fetch the target URL deterministically.
    
    - Resolves and strictly uses the IP address from SSRF Guard.
    - Preserves SNI by keeping the original hostname in the URL.
    - Handles redirects manually to maintain SSRF protections on redirect targets.
    - Captures response time, headers, and body.
    - Gracefully handles all network failures.
    """
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)
    
    current_url = url
    redirect_count = 0
    start_time = time.time()
    
    final_hostname = ""
    final_resolved_ip = ""
    
    while redirect_count <= MAX_REDIRECTS:
        parsed = urlparse(current_url)
        hostname = parsed.hostname
        
        if not hostname:
            return EvidenceError(
                error_type="INVALID_URL",
                message="URL does not contain a valid hostname.",
                url=current_url
            )
            
        # 1. SSRF Guard Check (DNS resolution & IP validation for the current hop)
        try:
            resolved_ip = ssrf_check(current_url)
        except SSRFError as e:
            return EvidenceError(
                error_type="SSRF_BLOCKED",
                message=str(e),
                url=current_url
            )
        except Exception as e:
            return EvidenceError(
                error_type="DNS_FAILURE",
                message=f"Failed to resolve hostname: {str(e)}",
                url=current_url
            )
            
        final_hostname = hostname
        final_resolved_ip = resolved_ip
        
        # 2. Execute Request with Thread-Safe DNS Override
        try:
            with ThreadSafeDNSOverride(hostname, resolved_ip):
                response = session.get(
                    current_url,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                    allow_redirects=False, # We handle redirects manually for SSRF safety
                    verify=True, # We can now safely verify SSL because the hostname is intact
                    stream=True # Prevent RAM exhaustion
                )
        except requests.exceptions.Timeout:
            return EvidenceError(error_type="TIMEOUT", message=f"Connection timed out after {REQUEST_TIMEOUT_SECONDS} seconds.", url=current_url)
        except requests.exceptions.SSLError as e:
            return EvidenceError(error_type="SSL_ERROR", message=f"SSL Verification failed: {str(e)}", url=current_url)
        except requests.exceptions.ConnectionError as e:
            return EvidenceError(error_type="CONNECTION_REFUSED", message="Failed to establish a connection to the server.", url=current_url)
        except Exception as e:
            return EvidenceError(error_type="HTTP_FAILURE", message=f"An unexpected HTTP error occurred: {str(e)}", url=current_url)
            
        # 3. Handle Manual Redirects
        if response.status_code in (301, 302, 303, 307, 308):
            redirect_count += 1
            location = response.headers.get("Location")
            if not location:
                break # Nowhere to redirect
            current_url = urljoin(current_url, location)
            continue
            
        # 4. Final Target Reached
        content_chunks = []
        bytes_downloaded = 0
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                content_chunks.append(chunk)
                bytes_downloaded += len(chunk)
                if bytes_downloaded > MAX_RESPONSE_BYTES:
                    # Truncate and close connection to prevent OOM
                    response.close()
                    break
                    
        content = b"".join(content_chunks).decode("utf-8", errors="replace")
        response_time = time.time() - start_time
        resp_headers = {k: v for k, v in response.headers.items()}
        
        return FetchResult(
            url=current_url,
            hostname=final_hostname,
            resolved_ip=final_resolved_ip,
            status_code=response.status_code,
            response_time=round(response_time, 3),
            headers=resp_headers,
            html_content=content
        )
        
    return EvidenceError(
        error_type="REDIRECT_LOOP",
        message=f"Exceeded maximum number of redirects ({MAX_REDIRECTS}).",
        url=current_url
    )

"""
security/url_validator.py — URL structure and scheme validation.

Validates that a user-supplied URL is structurally sound and uses
an allowed scheme before any network connection is made.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse


# ── Allowed schemes ───────────────────────────────────────────────────────────

ALLOWED_SCHEMES = {"http", "https"}
MAX_URL_LENGTH = 2048


# ── Public Interface ──────────────────────────────────────────────────────────

def validate(url: str) -> str:
    """
    Validate and normalise a target URL.

    Checks:
      - Non-empty after strip
      - Does not exceed MAX_URL_LENGTH
      - Scheme is http or https
      - Host component is present
      - No embedded credentials (user:pass@host)

    Returns the normalised URL on success.
    Raises ValueError with a user-safe message on any failure.
    """
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty.")
        
    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.")
        
    if not is_allowed_scheme(url):
        raise ValueError("Only 'http' and 'https' schemes are allowed.")
        
    if not has_valid_host(url):
        raise ValueError("URL must contain a valid host component.")
        
    return strip_credentials(url)


def is_allowed_scheme(url: str) -> bool:
    """Return True only if the URL scheme is in ALLOWED_SCHEMES."""
    try:
        parsed = urlparse(url)
        return parsed.scheme.lower() in ALLOWED_SCHEMES
    except Exception:
        return False


def has_valid_host(url: str) -> bool:
    """Return True if the URL contains a non-empty host component."""
    try:
        parsed = urlparse(url)
        return bool(parsed.hostname)
    except Exception:
        return False


def strip_credentials(url: str) -> str:
    """
    Remove embedded user:pass credentials from a URL.
    e.g. http://user:pass@example.com → http://example.com
    """
    parsed = urlparse(url)
    
    # If there's no username/password, just return the original (or unparsed)
    if not parsed.username and not parsed.password:
        return url
        
    # Reconstruct the netloc without credentials
    # parsed.hostname handles the extraction of the host without userinfo
    new_netloc = parsed.hostname
    if parsed.port:
        new_netloc = f"{new_netloc}:{parsed.port}"
        
    # Reconstruct the full URL
    new_url = urlunparse((
        parsed.scheme,
        new_netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))
    return new_url

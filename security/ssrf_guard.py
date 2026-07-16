"""
security/ssrf_guard.py — Server-Side Request Forgery (SSRF) prevention.

Resolves the target hostname and blocks requests to private, loopback,
link-local, and reserved IP ranges before any HTTP request is made.

This module is the primary SSRF defence layer.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


# ── Blocked IP ranges ─────────────────────────────────────────────────────────

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 private
    ipaddress.ip_network("127.0.0.0/8"),        # loopback
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("169.254.0.0/16"),     # link-local
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
    ipaddress.ip_network("100.64.0.0/10"),      # shared address space
    ipaddress.ip_network("0.0.0.0/8"),          # this network
    ipaddress.ip_network("240.0.0.0/4"),        # reserved
    ipaddress.ip_network("fc00::/7"),           # IPv6 unique local
    ipaddress.ip_network("metadata.google.internal/32") if False else
        ipaddress.ip_network("169.254.169.254/32"),  # cloud metadata endpoints
]

DNS_TIMEOUT_SECONDS = 5
MAX_REDIRECTS = 5


# ── Public Interface ──────────────────────────────────────────────────────────

def check(url: str) -> str:
    """
    Perform full SSRF guard on a URL.

    Steps:
      1. Resolve hostname to IP addresses
      2. Reject if any resolved IP falls in a blocked range
      3. Raise SSRFError with a user-safe message on any violation
      4. Return the safe IP address to be used for the actual request

    Raises SSRFError on failure.
    Raises socket.gaierror if DNS resolution fails.
    Returns the resolved IP address to prevent DNS rebinding.
    """
    ips = resolve_host(url)
    if not ips:
        raise SSRFError(f"Could not resolve any IP addresses for the host.")
        
    for ip in ips:
        if is_private_ip(ip):
            raise SSRFError(f"Security validation failed: Target resolves to a blocked or internal IP address ({ip}).")
            
    return ips[0]


def resolve_host(url: str) -> list[str]:
    """
    DNS-resolve the host component of a URL.
    Returns a list of resolved IP address strings.
    Raises socket.gaierror on resolution failure.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("URL does not contain a valid hostname.")
        
    # Set default timeout for socket operations during resolution
    socket.setdefaulttimeout(DNS_TIMEOUT_SECONDS)
    
    # Resolve the hostname. Using getaddrinfo allows resolving both IPv4 and IPv6
    try:
        # socket.AF_UNSPEC returns both IPv4 and IPv6
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        # Extract IP addresses (it's the first element of the sockaddr tuple in the 5th element)
        ips = [info[4][0] for info in addr_info]
        # De-duplicate
        return list(set(ips))
    except socket.gaierror as e:
        raise socket.gaierror(f"DNS resolution failed for {hostname}: {str(e)}")


def is_private_ip(ip: str) -> bool:
    """Return True if the given IP string falls within any blocked network."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in _BLOCKED_NETWORKS:
            if ip_obj in network:
                return True
        return False
    except ValueError:
        # If it's not a valid IP address format at all, block it to be safe
        return True


# ── Custom Exception ──────────────────────────────────────────────────────────

class SSRFError(ValueError):
    """Raised when a URL resolves to a blocked (private/reserved) IP address."""
    pass

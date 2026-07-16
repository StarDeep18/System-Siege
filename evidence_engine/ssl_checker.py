"""
evidence_engine/ssl_checker.py — TLS/SSL certificate inspection.

Performs deterministic TLS checks: certificate validity, expiry,
protocol version, and cipher strength.

All results are facts (not AI interpretations).
Uses the Python standard-library 'ssl' and 'socket' modules only.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse


# ── Configuration ─────────────────────────────────────────────────────────────

SSL_TIMEOUT_SECONDS = 10
EXPIRY_WARNING_DAYS = 30           # warn if cert expires within this many days


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class SSLResult:
    valid: bool
    grade: str                     # A | B | C | F | N/A
    subject: str
    issuer: str
    expires_at: Optional[datetime]
    days_until_expiry: Optional[int]
    protocol_version: str          # e.g. TLSv1.2, TLSv1.3
    cipher_suite: str
    score_impact: int              # points deducted from risk score
    issues: list[str] = field(default_factory=list)


# ── Public Interface ──────────────────────────────────────────────────────────

def check(url: str) -> Optional[SSLResult]:
    """
    Perform a full TLS inspection of the target URL.

    Returns an SSLResult with all collected certificate evidence.
    Returns None if the URL scheme is not HTTPS (HTTP targets have no TLS).
    Returns an SSLResult with valid=False and a descriptive issue on
    connection failure, so callers always receive a typed object.
    """
    parsed = urlparse(url)

    if parsed.scheme.lower() != "https":
        return None     # HTTP target — no TLS to inspect

    hostname = parsed.hostname
    port = parsed.port or 443

    if not hostname:
        return SSLResult(
            valid=False,
            grade="F",
            subject="",
            issuer="",
            expires_at=None,
            days_until_expiry=None,
            protocol_version="",
            cipher_suite="",
            score_impact=20,
            issues=["Could not extract a hostname from the URL."],
        )

    try:
        cert_info = get_certificate_info(hostname, port)
    except ssl.SSLCertVerificationError as exc:
        return SSLResult(
            valid=False,
            grade="F",
            subject=hostname,
            issuer="",
            expires_at=None,
            days_until_expiry=None,
            protocol_version="",
            cipher_suite="",
            score_impact=25,
            issues=[f"Certificate verification failed: {exc}"],
        )
    except ssl.SSLError as exc:
        return SSLResult(
            valid=False,
            grade="F",
            subject=hostname,
            issuer="",
            expires_at=None,
            days_until_expiry=None,
            protocol_version="",
            cipher_suite="",
            score_impact=20,
            issues=[f"TLS handshake error: {exc}"],
        )
    except (socket.timeout, TimeoutError):
        return SSLResult(
            valid=False,
            grade="F",
            subject=hostname,
            issuer="",
            expires_at=None,
            days_until_expiry=None,
            protocol_version="",
            cipher_suite="",
            score_impact=15,
            issues=["TLS connection timed out."],
        )
    except Exception as exc:
        return SSLResult(
            valid=False,
            grade="F",
            subject=hostname,
            issuer="",
            expires_at=None,
            days_until_expiry=None,
            protocol_version="",
            cipher_suite="",
            score_impact=15,
            issues=[f"Unexpected error during TLS inspection: {exc}"],
        )

    return compute_ssl_grade(cert_info)


def get_certificate_info(hostname: str, port: int = 443) -> dict:
    """
    Connect to hostname:port and return a dict with:
      - cert: the DER-decoded certificate dict from ssl
      - protocol: negotiated TLS protocol version string
      - cipher: negotiated cipher suite name
    Raises ssl.SSLError or socket.error on failure.
    """
    context = ssl.create_default_context()

    conn = socket.create_connection((hostname, port), timeout=SSL_TIMEOUT_SECONDS)
    try:
        tls_sock = context.wrap_socket(conn, server_hostname=hostname)
        try:
            cert = tls_sock.getpeercert()          # decoded dict
            protocol = tls_sock.version()          # e.g. "TLSv1.3"
            cipher_name, _, _ = tls_sock.cipher()  # e.g. "TLS_AES_256_GCM_SHA384"
        finally:
            tls_sock.close()
    finally:
        conn.close()

    return {
        "cert": cert,
        "protocol": protocol or "",
        "cipher": cipher_name or "",
        "hostname": hostname,
    }


def compute_ssl_grade(cert_data: dict) -> SSLResult:
    """
    Compute a letter grade from real certificate and protocol evidence.

    Grades:
        A  — TLS 1.3 + valid cert + no expiry warning
        B  — TLS 1.2 + valid cert + no expiry warning
        C  — TLS 1.2 with expiry warning, or weak cipher
        F  — Invalid, expired, or self-signed cert
    """
    cert = cert_data.get("cert", {})
    protocol = cert_data.get("protocol", "")
    cipher = cert_data.get("cipher", "")
    hostname = cert_data.get("hostname", "")

    issues: list[str] = []
    penalty = 0

    # ── Extract subject ───────────────────────────────────────────────────────
    subject_rdns = cert.get("subject", ())
    subject = _extract_cn(subject_rdns) or hostname

    # ── Extract issuer ────────────────────────────────────────────────────────
    issuer_rdns = cert.get("issuer", ())
    issuer = _extract_cn(issuer_rdns) or "Unknown"

    # ── Expiry ────────────────────────────────────────────────────────────────
    not_after_str = cert.get("notAfter", "")
    expires_at: Optional[datetime] = None
    days_left: Optional[int] = None

    if not_after_str:
        try:
            expires_at = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (expires_at - datetime.now(timezone.utc)).days
        except ValueError:
            issues.append(f"Could not parse certificate expiry date: '{not_after_str}'")

    if days_left is not None:
        if days_left < 0:
            issues.append(f"Certificate has EXPIRED ({abs(days_left)} days ago).")
            penalty += 30
        elif days_left <= EXPIRY_WARNING_DAYS:
            issues.append(f"Certificate expires in {days_left} days (within warning threshold).")
            penalty += 10

    # ── Protocol strength ─────────────────────────────────────────────────────
    protocol_upper = protocol.upper()
    if protocol_upper in ("SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"):
        issues.append(f"Deprecated protocol in use: {protocol}.")
        penalty += 20
    elif protocol_upper == "TLSV1.2":
        pass  # Acceptable, no penalty
    elif protocol_upper == "TLSV1.3":
        pass  # Ideal
    elif protocol:
        issues.append(f"Unknown or unrecognised protocol: {protocol}.")
        penalty += 5

    # ── Cipher strength ───────────────────────────────────────────────────────
    cipher_upper = cipher.upper()
    weak_ciphers = ("RC4", "DES", "3DES", "NULL", "EXPORT", "ANON")
    if any(weak in cipher_upper for weak in weak_ciphers):
        issues.append(f"Weak or deprecated cipher suite in use: {cipher}.")
        penalty += 15

    # ── Determine validity and grade ──────────────────────────────────────────
    expired = (days_left is not None and days_left < 0)
    valid = not expired

    penalty = min(penalty, 30)  # cap SSL penalty at 30 pts

    if not valid or penalty >= 30:
        grade = "F"
    elif penalty >= 15:
        grade = "C"
    elif protocol_upper == "TLSV1.3" and not issues:
        grade = "A"
    else:
        grade = "B"

    return SSLResult(
        valid=valid,
        grade=grade,
        subject=subject,
        issuer=issuer,
        expires_at=expires_at,
        days_until_expiry=days_left,
        protocol_version=protocol,
        cipher_suite=cipher,
        score_impact=penalty,
        issues=issues,
    )


def days_until_expiry(not_after: str) -> int:
    """Parse an SSL not_after date string and return days remaining."""
    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )
    return (expires - datetime.now(timezone.utc)).days


# ── Private Helpers ───────────────────────────────────────────────────────────

def _extract_cn(rdns_tuple: tuple) -> str:
    """Extract the Common Name (CN) value from a DER-decoded RDN sequence."""
    for rdn in rdns_tuple:
        for attr in rdn:
            if attr[0] == "commonName":
                return attr[1]
    return ""

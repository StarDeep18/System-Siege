"""
evidence_engine/headers.py — HTTP security header analysis.

Inspects HTTP response headers for missing or misconfigured security
controls. Produces structured SecurityHeaderFinding records.

All logic is deterministic. No AI involvement.
"""

from __future__ import annotations

from dataclasses import dataclass


# ── Required Security Headers ─────────────────────────────────────────────────

REQUIRED_HEADERS = {
    "content-security-policy": {
        "owasp": "A05:2021 – Security Misconfiguration",
        "score_impact": 20,
        "severity": "high",
        "recommendation": (
            "Add a Content-Security-Policy header restricting script, style, and "
            "frame sources to trusted origins. Example: "
            "Content-Security-Policy: default-src 'self'"
        ),
    },
    "strict-transport-security": {
        "owasp": "A02:2021 – Cryptographic Failures",
        "score_impact": 15,
        "severity": "high",
        "recommendation": (
            "Enable HTTP Strict Transport Security (HSTS) with a minimum age of "
            "31536000 seconds and includeSubDomains. Example: "
            "Strict-Transport-Security: max-age=31536000; includeSubDomains"
        ),
    },
    "x-frame-options": {
        "owasp": "A05:2021 – Security Misconfiguration",
        "score_impact": 10,
        "severity": "medium",
        "recommendation": (
            "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking. "
            "Example: X-Frame-Options: DENY"
        ),
    },
    "x-content-type-options": {
        "owasp": "A05:2021 – Security Misconfiguration",
        "score_impact": 5,
        "severity": "low",
        "recommendation": (
            "Set X-Content-Type-Options: nosniff to prevent MIME type sniffing attacks."
        ),
    },
    "referrer-policy": {
        "owasp": "A05:2021 – Security Misconfiguration",
        "score_impact": 5,
        "severity": "low",
        "recommendation": (
            "Set Referrer-Policy to control how much referrer information is sent. "
            "Example: Referrer-Policy: strict-origin-when-cross-origin"
        ),
    },
    "permissions-policy": {
        "owasp": "A05:2021 – Security Misconfiguration",
        "score_impact": 5,
        "severity": "low",
        "recommendation": (
            "Add a Permissions-Policy header to restrict browser feature access. "
            "Example: Permissions-Policy: geolocation=(), microphone=()"
        ),
    },
}

INFORMATION_LEAKING_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class SecurityHeaderFinding:
    header_name: str
    present: bool
    value: str                   # empty string if absent
    severity: str                # critical | high | medium | low
    owasp_category: str
    score_impact: int
    recommendation: str


# ── Public Interface ──────────────────────────────────────────────────────────

def analyse(response_headers: dict) -> list[SecurityHeaderFinding]:
    """
    Analyse HTTP response headers and return a list of SecurityHeaderFindings.
    Checks for missing required headers and information-leaking headers.
    """
    findings: list[SecurityHeaderFinding] = []
    findings.extend(check_required_headers(response_headers))
    findings.extend(check_information_leakage(response_headers))
    return findings


def check_required_headers(response_headers: dict) -> list[SecurityHeaderFinding]:
    """Check all REQUIRED_HEADERS against the response headers dict."""
    # Normalise to lowercase keys for case-insensitive comparison
    lower_headers = {k.lower(): v for k, v in response_headers.items()}
    findings: list[SecurityHeaderFinding] = []

    for header_name, meta in REQUIRED_HEADERS.items():
        present = header_name in lower_headers
        value = lower_headers.get(header_name, "")

        findings.append(SecurityHeaderFinding(
            header_name=header_name,
            present=present,
            value=value,
            severity=meta["severity"],
            owasp_category=meta["owasp"],
            # Only penalise score if the header is absent
            score_impact=0 if present else meta["score_impact"],
            recommendation=meta["recommendation"],
        ))

    return findings


def check_information_leakage(response_headers: dict) -> list[SecurityHeaderFinding]:
    """Flag headers that leak server technology information."""
    lower_headers = {k.lower(): v for k, v in response_headers.items()}
    findings: list[SecurityHeaderFinding] = []

    for header_name in INFORMATION_LEAKING_HEADERS:
        if header_name in lower_headers:
            value = lower_headers[header_name]
            findings.append(SecurityHeaderFinding(
                header_name=header_name,
                present=True,
                value=value,
                severity="medium",
                owasp_category="A05:2021 – Security Misconfiguration",
                score_impact=5,
                recommendation=(
                    f"Remove or suppress the '{header_name}' header. "
                    f"It currently discloses: '{value}'. "
                    "This information aids attacker reconnaissance. "
                    "Configure the server to omit this header entirely."
                ),
            ))

    return findings

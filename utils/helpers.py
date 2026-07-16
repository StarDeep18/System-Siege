"""
utils/helpers.py — Shared formatting utilities and application-wide constants.
"""

from __future__ import annotations

from datetime import datetime, timezone


# ── Constants ─────────────────────────────────────────────────────────────────

RISK_LEVELS = {
    "critical": (80, 100),
    "high": (60, 79),
    "medium": (40, 59),
    "low": (0, 39),
}

RISK_COLORS = {
    "critical": "#FF4C4C",
    "high": "#FF8C00",
    "medium": "#FFD700",
    "low": "#00E5A0",
}

OWASP_CATEGORIES = [
    "A01:2021 – Broken Access Control",
    "A02:2021 – Cryptographic Failures",
    "A03:2021 – Injection",
    "A04:2021 – Insecure Design",
    "A05:2021 – Security Misconfiguration",
    "A06:2021 – Vulnerable and Outdated Components",
    "A07:2021 – Identification and Authentication Failures",
    "A08:2021 – Software and Data Integrity Failures",
    "A09:2021 – Security Logging and Monitoring Failures",
    "A10:2021 – Server-Side Request Forgery",
]


# ── Date / Time ───────────────────────────────────────────────────────────────

def utc_now() -> datetime:
    """Return the current UTC datetime."""
    return datetime.now(timezone.utc)


def format_timestamp(dt: datetime) -> str:
    """Format a datetime as a human-readable string (e.g. '16 Jul 2026, 09:45')."""
    pass


def time_ago(dt: datetime) -> str:
    """Return a relative time string (e.g. '3 minutes ago', '2 days ago')."""
    pass


# ── Risk Score ────────────────────────────────────────────────────────────────

def score_to_level(score: int) -> str:
    """Map a 0–100 risk score to a risk level string."""
    pass


def score_to_color(score: int) -> str:
    """Map a 0–100 risk score to its hex colour string."""
    pass


# ── Formatting ────────────────────────────────────────────────────────────────

def truncate(text: str, max_chars: int = 80) -> str:
    """Truncate text and append '…' if it exceeds max_chars."""
    pass


def domain_from_url(url: str) -> str:
    """Extract the domain name from a full URL."""
    pass

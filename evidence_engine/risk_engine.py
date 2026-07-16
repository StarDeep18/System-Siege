"""
evidence_engine/risk_engine.py — Deterministic risk score calculation.

Aggregates all evidence from headers, SSL, and diff analysis into a
single 0–100 risk score and a structured EvidenceReport.

The EvidenceReport is the ONLY object passed to the AI Incident
Intelligence layer. It contains no raw HTML, no JavaScript, and no
user-controlled web content.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from evidence_engine.vulnerability import Vulnerability
from evidence_engine.headers import SecurityHeaderFinding
from evidence_engine.ssl_checker import SSLResult
from evidence_engine.diff import DiffResult


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class EvidenceReport:
    """
    The complete, structured output of the Evidence Engine.

    This is the contract between the Evidence Engine and the AI layer.

    INVARIANT: This object must NEVER contain:
      - raw HTML
      - JavaScript
      - CSS
      - Markdown from the scanned page
      - Any other user-controlled web content

    The AI layer receives this object and this object only.
    """
    url: str
    scanned_at: datetime

    # ── Risk Summary ──────────────────────────────────────────────────────────
    risk_score: int                          # 0–100 (100 = safest)
    risk_level: str                          # critical | high | medium | low

    # ── TLS Evidence ──────────────────────────────────────────────────────────
    https_enabled: bool
    ssl: Optional[SSLResult]

    # ── Header Evidence ───────────────────────────────────────────────────────
    header_findings: list[SecurityHeaderFinding] = field(default_factory=list)

    # ── Defacement Evidence ───────────────────────────────────────────────────
    defacement_detected: bool = False
    diff: Optional[DiffResult] = None

    # ── Aggregated Vulnerabilities ────────────────────────────────────────────
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    # ── HTTP Metadata ─────────────────────────────────────────────────────────
    status_code: int = 200
    redirect_count: int = 0
    response_size_bytes: int = 0
    server_header: str = ""          # server tech disclosure (if present)


# ── Public Interface ──────────────────────────────────────────────────────────

def build_report(
    url: str,
    header_findings: list[SecurityHeaderFinding],
    ssl_result: Optional[SSLResult],
    diff_result: Optional[DiffResult],
    fetch_meta: dict,
) -> EvidenceReport:
    """
    Aggregate all evidence into an EvidenceReport.
    Computes the final risk_score and risk_level.
    """
    pass


def compute_risk_score(
    header_findings: list[SecurityHeaderFinding],
    ssl_result: Optional[SSLResult],
    diff_result: Optional[DiffResult],
) -> int:
    """
    Compute a 0–100 risk score from all evidence sources.
    Starts at 100 and deducts points for each finding's score_impact.
    Score is clamped to [0, 100].
    """
    pass


def score_to_level(score: int) -> str:
    """Map a 0–100 risk score to a risk level string."""
    if score >= 80:
        return "low"
    elif score >= 60:
        return "medium"
    elif score >= 40:
        return "high"
    else:
        return "critical"


def to_firestore_dict(report: EvidenceReport) -> dict:
    """Serialise an EvidenceReport to a Firestore-compatible dict."""
    pass

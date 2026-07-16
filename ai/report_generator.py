"""
ai/report_generator.py — AI-powered executive report generation.

Receives an EvidenceReport and XAIOutput.
Produces a human-readable executive summary and remediation plan.

HARD RULE: This module must never receive raw HTML, JavaScript, CSS,
or any user-controlled web content.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime

import google.generativeai as genai

from evidence_engine.risk_engine import EvidenceReport
from ai.explainability import XAIOutput
from ai.attack_story import AttackStory


# ── Configuration ─────────────────────────────────────────────────────────────

_MODEL_NAME = "gemini-1.5-flash"


def _get_client() -> genai.GenerativeModel:
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        raise EnvironmentError("GEMINI_API_KEY is not set.")
    genai.configure(api_key=api_key)
    return genai.GenerativeModel(_MODEL_NAME)


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class ExecutiveReport:
    """
    A structured report combining deterministic evidence and AI interpretation.
    Suitable for export to PDF or display in the Reports page.
    """
    generated_at: datetime
    url: str
    risk_score: int
    risk_level: str
    executive_summary: str
    key_findings: list[str] = field(default_factory=list)
    remediation_plan: list[str] = field(default_factory=list)
    compliance_notes: str = ""


# ── Public Interface ──────────────────────────────────────────────────────────

def generate(
    report: EvidenceReport,
    xai: XAIOutput,
    story: AttackStory,
) -> ExecutiveReport:
    """
    Generate an ExecutiveReport from structured evidence and AI output.
    Raises RuntimeError on API failure.
    """
    pass


def build_prompt(report: EvidenceReport, xai: XAIOutput) -> str:
    """Build the report generation prompt from structured data only."""
    pass


def parse_response(raw: str, report: EvidenceReport) -> ExecutiveReport:
    """Parse the Gemini response into an ExecutiveReport object."""
    pass


def to_firestore_dict(exec_report: ExecutiveReport) -> dict:
    """Serialise an ExecutiveReport to a Firestore-compatible dict."""
    pass

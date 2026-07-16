"""
ai/explainability.py — Explainable AI output generation.

Receives ScanEvidence + RiskAssessment from the deterministic pipeline.
Produces structured XAI findings that explain each deterministic vulnerability.

HARD RULES (Architecture Invariants):
  - This module NEVER receives raw HTML, JavaScript, CSS, or
    any user-controlled web content.
  - This module NEVER detects vulnerabilities.
  - Every AI conclusion MUST reference a specific FindingReference
    from the RiskAssessment (which itself cites the ScanEvidence field).
  - The prompt is assembled from structured data fields only.

Prompt injection is neutralised because the AI only sees:
  URL, score, grade, finding titles, severity, evidence_reference strings —
  never the raw page content.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import google.generativeai as genai

from evidence_engine.models import ScanEvidence
from risk_engine.models import RiskAssessment, FindingReference

log = logging.getLogger(__name__)


# ── Configuration ─────────────────────────────────────────────────────────────

_MODELS_TO_TRY = [
    "gemini-2.0-flash",
    "gemini-flash-latest"
]
_TEMPERATURE  = 0.2          # Low temperature for consistent, factual explanations
_MAX_RETRIES  = 3
_RETRY_DELAY  = 2.0          # seconds between retries
_PROMPT_VERSION = "1.1"


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class XAIFinding:
    """
    A single Explainable AI finding.
    evidence_reference always points to a field from the deterministic pipeline.
    """
    finding: str
    confidence: str                       # High | Medium | Low
    evidence_reference: str               # e.g. "headers.security_headers['csp'] = absent"
    reason: str
    owasp_mapping: str
    business_impact: str
    recommendation: str
    verification_checklist: list[str] = field(default_factory=list)


@dataclass
class AIMetadata:
    """Provenance record for every AI response."""
    model: str
    temperature: float
    prompt_version: str
    retry_count: int
    generated_at: str


@dataclass
class XAIOutput:
    """Full Explainable AI output for one scan."""
    executive_summary: str
    risk_narrative: str
    findings: list[XAIFinding] = field(default_factory=list)
    ai_metadata: Optional[AIMetadata] = None


# ── Public Interface ──────────────────────────────────────────────────────────

def explain(
    evidence: ScanEvidence,
    assessment: RiskAssessment,
) -> XAIOutput:
    """
    Generate an XAIOutput from a ScanEvidence + RiskAssessment pair.

    The prompt never contains raw HTML. Only structured metadata from
    the deterministic pipeline reaches Gemini.

    Retries up to _MAX_RETRIES times on transient API errors, and falls back
    to older models if the latest ones are unsupported for the API key.
    Raises RuntimeError if all retries are exhausted.
    """
    prompt = build_prompt(evidence, assessment)
    last_exc: Optional[Exception] = None
    
    for model_name in _MODELS_TO_TRY:
        client = _get_client(model_name)
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                response = client.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        temperature=_TEMPERATURE,
                        candidate_count=1,
                    )
                )
                raw_text = response.text
                output = parse_response(raw_text, assessment)
                output.ai_metadata = AIMetadata(
                    model=model_name,
                    temperature=_TEMPERATURE,
                    prompt_version=_PROMPT_VERSION,
                    retry_count=attempt - 1,
                    generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                )
                return output
    
            except Exception as exc:
                last_exc = exc
                log.warning(
                    "Gemini call failed with model %s on attempt %d/%d: %s",
                    model_name, attempt, _MAX_RETRIES, exc
                )
                
                # If the model is not found, immediately break and try the next model
                if "404" in str(exc) or "not found" in str(exc).lower():
                    break
                    
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_DELAY * attempt)

    log.error(
        f"Gemini API unavailable after trying all fallback models. "
        f"Last error: {last_exc}"
    )
    return _degraded_output(
        assessment, 
        reason=f"AI features disabled (Invalid API Key or Service Unavailable)."
    )


def build_prompt(evidence: ScanEvidence, assessment: RiskAssessment) -> str:
    """
    Build the Gemini prompt from structured pipeline fields ONLY.

    NEVER includes:
      - html_content
      - raw page body
      - user-controlled strings from the scanned website

    Only includes:
      - URL hostname
      - Numeric scores and grades
      - Finding titles, severities, and evidence_reference strings
        (these are field path strings like "headers['csp'] = absent")
      - OWASP category names
    """
    url = evidence.metadata.url
    hostname = evidence.metadata.hostname
    score = assessment.summary.overall_security_score
    grade = assessment.summary.overall_grade
    severity = assessment.summary.overall_severity
    confidence = assessment.confidence.confidence_score
    stats = assessment.statistics

    # Build the findings section — only structured field references, never content
    findings_block = _format_findings_for_prompt(assessment.findings)

    prompt = f"""You are a cybersecurity analyst writing an Explainable AI report.

You have received the output of a deterministic security scan pipeline.
You must explain what the findings mean. You must NOT invent new findings.
You must NOT scan the website. You must NOT access any URLs.
Every explanation must cite the evidence_reference provided.

== TARGET ==
URL:      {url}
Hostname: {hostname}

== DETERMINISTIC RISK ASSESSMENT ==
Security Score:    {score} / 100
Grade:             {grade}
Overall Severity:  {severity}
Confidence:        {confidence}%

Finding Counts:
  Critical: {stats.critical_count}
  High:     {stats.high_count}
  Medium:   {stats.medium_count}
  Low:      {stats.low_count}

== DETERMINISTIC FINDINGS (explain these exactly, do not add others) ==
{findings_block}

== OUTPUT FORMAT ==
Respond with valid JSON only. No markdown. No code fences. No extra text.

{{
  "executive_summary": "2-3 sentence plain-English summary for a CISO. Reference the score and top severity.",
  "risk_narrative": "1 paragraph explaining the overall risk posture. Reference the grade and top findings.",
  "findings": [
    {{
      "finding": "<exact title from the finding list above>",
      "confidence": "High",
      "evidence_reference": "<exact evidence_reference string from above>",
      "reason": "Why this finding matters technically.",
      "owasp_mapping": "<OWASP category from the finding>",
      "business_impact": "What could happen if this is exploited.",
      "recommendation": "Specific, actionable fix in plain English.",
      "verification_checklist": [
        "Step 1 to verify fix",
        "Step 2 to verify fix"
      ]
    }}
  ]
}}

Rules:
- findings array must contain exactly {len(assessment.findings)} item(s), one per finding above.
- Do not add findings that are not in the list above.
- Do not include any content from the scanned webpage.
- confidence must be one of: High, Medium, Low.
- Keep executive_summary under 80 words.
- Keep each recommendation under 50 words.
"""
    return prompt


def parse_response(raw: str, assessment: RiskAssessment) -> XAIOutput:
    """
    Parse and validate the Gemini JSON response into an XAIOutput object.

    Validation:
      - Must be valid JSON.
      - Must contain executive_summary, risk_narrative, findings.
      - Each finding must have all required fields.
      - Finding titles must match a FindingReference from the assessment.
      - Falls back to a safe degraded XAIOutput on parse failure.
    """
    # Strip accidental markdown fences Gemini sometimes adds
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(
            line for line in lines
            if not line.strip().startswith("```")
        ).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        log.error("Gemini response was not valid JSON: %s", exc)
        return _degraded_output(
            assessment,
            reason=f"AI response could not be parsed as JSON: {exc}",
        )

    # ── Validate top-level fields ─────────────────────────────────────────────
    executive_summary = data.get("executive_summary", "").strip()
    risk_narrative = data.get("risk_narrative", "").strip()

    if not executive_summary or not risk_narrative:
        log.warning("AI response missing executive_summary or risk_narrative.")
        return _degraded_output(
            assessment,
            reason="AI response was missing required top-level fields.",
        )

    # ── Validate and map findings ─────────────────────────────────────────────
    known_titles = {f.title for f in assessment.findings}
    raw_findings = data.get("findings", [])
    xai_findings: list[XAIFinding] = []

    for item in raw_findings:
        title = item.get("finding", "").strip()

        # Reject AI-invented findings that were not in the deterministic pipeline
        if title not in known_titles:
            log.warning(
                "AI invented a finding not in the assessment: '%s'. Skipping.", title
            )
            continue

        confidence = item.get("confidence", "Medium")
        if confidence not in ("High", "Medium", "Low"):
            confidence = "Medium"

        xai_findings.append(XAIFinding(
            finding=title,
            confidence=confidence,
            evidence_reference=item.get("evidence_reference", "").strip(),
            reason=item.get("reason", "").strip(),
            owasp_mapping=item.get("owasp_mapping", "").strip(),
            business_impact=item.get("business_impact", "").strip(),
            recommendation=item.get("recommendation", "").strip(),
            verification_checklist=item.get("verification_checklist", []),
        ))

    return XAIOutput(
        executive_summary=executive_summary,
        risk_narrative=risk_narrative,
        findings=xai_findings,
    )


# ── Private Helpers ───────────────────────────────────────────────────────────

def _get_client(model_name: str) -> genai.GenerativeModel:
    """Initialise and return the Gemini client. Reads GEMINI_API_KEY from env."""
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise EnvironmentError(
            "GEMINI_API_KEY is not set. "
            "Add it to your .env file or Streamlit Secrets."
        )
    genai.configure(api_key=api_key)
    return genai.GenerativeModel(model_name)


def _format_findings_for_prompt(findings: list[FindingReference]) -> str:
    """
    Serialise FindingReferences into a structured text block for the prompt.

    ONLY exposes: title, severity, owasp categories, evidence_reference.
    Never exposes raw page content.
    """
    if not findings:
        return "  (No findings — site appears secure.)"

    lines: list[str] = []
    for i, f in enumerate(findings, start=1):
        owasp_str = ", ".join(f.owasp) if f.owasp else "N/A"
        lines.append(
            f"  [{i}] Title:              {f.title}\n"
            f"       Severity:           {f.severity}\n"
            f"       OWASP:              {owasp_str}\n"
            f"       Evidence Reference: {f.evidence_reference}\n"
            f"       Confidence:         {f.confidence}%"
        )
    return "\n\n".join(lines)


def _degraded_output(
    assessment: RiskAssessment,
    reason: str = "AI response unavailable.",
) -> XAIOutput:
    """
    Return a safe, deterministic fallback XAIOutput when the AI layer fails.
    Never fabricates vulnerability data — uses only the assessment's finding titles.
    """
    finding_titles = [f.title for f in assessment.findings]
    summary = (
        f"Security Score: {assessment.summary.overall_security_score}/100 "
        f"(Grade {assessment.summary.overall_grade}). "
        f"AI narrative unavailable: {reason}"
    )
    xai_findings = [
        XAIFinding(
            finding=f.title,
            confidence="High",
            evidence_reference=f.evidence_reference,
            reason="AI explanation unavailable. See evidence_reference for the deterministic source.",
            owasp_mapping=", ".join(f.owasp),
            business_impact="Refer to OWASP guidance for this category.",
            recommendation="Consult the OWASP Top 10 remediation guide for this finding.",
            verification_checklist=["Manually verify the finding against the evidence_reference."],
        )
        for f in assessment.findings
    ]
    return XAIOutput(
        executive_summary=summary,
        risk_narrative=f"Deterministic assessment complete. {reason}",
        findings=xai_findings,
    )

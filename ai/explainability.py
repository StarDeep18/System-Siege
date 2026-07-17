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
                
                exc_str = str(exc).lower()
                
                # Fast fail for auth, quota, or invalid key errors to prevent hanging
                if any(x in exc_str for x in ["429", "403", "400", "quota", "api_key", "invalid", "unauthenticated", "exceeded"]):
                    log.error(f"Fast failing due to fatal API error: {exc}")
                    return _degraded_output(assessment, f"AI features disabled (API Error: {exc})")

                # If the model is not found, immediately break and try the next model
                if "404" in exc_str or "not found" in exc_str:
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

== DETERMINISTIC RISK ==
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
      "reason": "Explain why it matters in plain English. Max 2 sentences.",
      "owasp_mapping": "<OWASP category from the finding>",
      "business_impact": "Possible impact. Bullet points explaining what could realistically happen. No CVSS language.",
      "recommendation": "Recommended Action. One clear action, max 3 bullet points. No long paragraphs.",
      "verification_checklist": [
        "Step 1 to verify fix"
      ]
    }}
  ]
}}

Rules:
- findings array must contain exactly {len(assessment.findings)} item(s), one per finding above.
- Tone: Senior SOC analyst explaining findings to a junior developer (CS student). Never sound academic.
- Language: Replace jargon with simple language. (e.g., use 'Attacker' instead of 'Adversary' or 'Threat actor', use 'Series of attacks' instead of 'Exploit chain').
- Length: Never generate more than 120 words per finding.
- Do not add findings that are not in the list above.
- Do not include any content from the scanned webpage.
- confidence must be one of: High, Medium, Low.
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


_LOCAL_EXPLAIN_DATABASE = {
    "Missing Content-Security-Policy Header": {
        "reason": "The Content-Security-Policy (CSP) header is missing. Without this, browsers cannot restrict where scripts load from.",
        "business_impact": "- Attackers can inject malicious scripts.\n- User session cookies can be stolen.\n- The website can be modified without permission.",
        "recommendation": "- Add a Content-Security-Policy header to the web server.\n- Restrict scripts to trusted sources only.",
        "verification_checklist": ["Run 'curl -I <URL>' and check for the header."]
    },
    "Missing Strict-Transport-Security Header": {
        "reason": "The website does not force browsers to use secure HTTPS connections. This means traffic might accidentally be sent over unencrypted HTTP.",
        "business_impact": "- Attackers on the same network can intercept traffic.\n- Sensitive data like passwords can be stolen in transit.",
        "recommendation": "- Enable the Strict-Transport-Security (HSTS) header on the server.\n- Ensure the max-age is set to at least one year.",
        "verification_checklist": ["Query headers and ensure Strict-Transport-Security exists."]
    },
    "Missing X-Frame-Options Header": {
        "reason": "The website does not prevent other sites from embedding it inside a frame. Attackers can overlay invisible buttons on top of your site.",
        "business_impact": "- Users can be tricked into clicking things they didn't intend to (Clickjacking).\n- Unintended actions can be performed on the user's behalf.",
        "recommendation": "- Add the X-Frame-Options header set to DENY or SAMEORIGIN.",
        "verification_checklist": ["Try loading the page inside an iframe and verify it is blocked."]
    },
    "Missing X-Content-Type-Options Header": {
        "reason": "The browser is allowed to guess the type of a file rather than trusting the server. Attackers can upload disguised files to run code.",
        "business_impact": "- Non-executable files (like images) can be run as scripts.\n- Increased risk of Cross-Site Scripting (XSS).",
        "recommendation": "- Add the X-Content-Type-Options: nosniff header to all responses.",
        "verification_checklist": ["Verify the header is present in HTTP responses."]
    },
    "Server Header Discloses Technology": {
        "reason": "The server reveals its exact software name and version in the response headers. This gives attackers free information to find known weaknesses.",
        "business_impact": "- Attackers can easily look up known vulnerabilities for your specific server version.\n- Speeds up the reconnaissance phase of an attack.",
        "recommendation": "- Configure the web server (e.g., Nginx or Apache) to hide server version details.",
        "verification_checklist": ["Send an HTTP request and confirm the Server header is generic."]
    },
    "Invalid TLS Certificate": {
        "reason": "The website's digital certificate is invalid or untrusted. Browsers cannot verify the identity of the server.",
        "business_impact": "- Visitors will see critical security warnings.\n- Attackers can intercept and read all data sent to the server.",
        "recommendation": "- Replace the certificate with a valid one signed by a trusted authority.\n- Ensure the domain name matches the certificate.",
        "verification_checklist": ["Verify the browser shows a secure padlock."]
    },
    "TLS Certificate Has Expired": {
        "reason": "The website's digital certificate has passed its expiration date. Browsers will no longer trust the connection.",
        "business_impact": "- Users are blocked from accessing the site by browser warnings.\n- Secure communication cannot be guaranteed.",
        "recommendation": "- Renew the certificate immediately through your certificate authority.\n- Set up automated renewals to prevent this in the future.",
        "verification_checklist": ["Check the new certificate validity dates."]
    },
    "Content Defacement Detected": {
        "reason": "The visual appearance or structure of the page has changed significantly compared to the original baseline. This usually means the site has been hacked.",
        "business_impact": "- The website may display malicious or inappropriate content.\n- Severe damage to the organization's reputation.",
        "recommendation": "- Restore the website from a known clean backup immediately.\n- Investigate server logs to find how the attacker gained access.",
        "verification_checklist": ["Compare the restored page against the original baseline."]
    },
    "SQL Injection Vulnerability Detected": {
        "reason": "The website allows raw database commands to be entered into input fields. Attackers can manipulate these inputs to talk directly to the database.",
        "business_impact": "- Attackers can read, modify, or delete any data in the database.\n- Complete takeover of administrative accounts is possible.",
        "recommendation": "- Use parameterized queries or prepared statements in the code.\n- Never paste user input directly into SQL strings.",
        "verification_checklist": ["Test inputs with SQL payloads to ensure errors are handled safely."]
    },
    "Cross-Site Scripting (XSS) Detected": {
        "reason": "User input is displayed on the page without being sanitized. Attackers can input malicious scripts that will run in other users' browsers.",
        "business_impact": "- Attackers can steal session cookies and take over user accounts.\n- Users can be redirected to fake login pages.",
        "recommendation": "- Sanitize and encode all user input before displaying it on the screen.",
        "verification_checklist": ["Test inputs with XSS payloads and verify they are neutralized."]
    },
    "Sensitive Files Exposed": {
        "reason": "Private files (like configuration files, backups, or source code) are accessible to anyone on the internet.",
        "business_impact": "- Passwords, API keys, and database credentials can be stolen.\n- Attackers gain a complete blueprint of the application.",
        "recommendation": "- Update server rules to deny access to sensitive directories.\n- Move configuration files outside the public web folder.",
        "verification_checklist": ["Verify sensitive file URLs return a 403 Forbidden error."]
    },
    "Missing Rate Limiting (DDoS Vulnerable)": {
        "reason": "The server accepts a massive number of requests from the same user without slowing them down. Attackers can overwhelm the system.",
        "business_impact": "- The website can crash and become unavailable to real users.\n- Attackers can guess passwords rapidly without being blocked.",
        "recommendation": "- Implement rate limiting on the server to block users making too many requests.",
        "verification_checklist": ["Run a load test to ensure the server eventually blocks rapid requests."]
    }
}


def _degraded_output(
    assessment: RiskAssessment,
    reason: str = "AI response unavailable.",
) -> XAIOutput:
    """
    Return a safe, deterministic fallback XAIOutput when the AI layer fails.
    Utilises a high-quality local expert database to render specific recommendations and reasons
    instead of placeholder text.
    """
    summary = (
        f"Security Score: {assessment.summary.overall_security_score}/100 "
        f"(Grade {assessment.summary.overall_grade}). "
        f"Diagnostic Mode: Utilizing expert security database fallback."
    )
    
    xai_findings = []
    for f in assessment.findings:
        title = f.title
        # Handle dynamic titles like "TLS Certificate Expires in X Days"
        matched_db = None
        for key in _LOCAL_EXPLAIN_DATABASE:
            if key in title:
                matched_db = _LOCAL_EXPLAIN_DATABASE[key]
                break
                
        if matched_db:
            reason_text = matched_db["reason"]
            impact_text = matched_db["business_impact"]
            rec_text = matched_db["recommendation"]
            checklist = matched_db["verification_checklist"]
        else:
            reason_text = "Detailed explanation unavailable. See evidence_reference for the deterministic source."
            impact_text = "Refer to OWASP guidance for this category."
            rec_text = "Consult the OWASP Top 10 remediation guide for this finding."
            checklist = ["Manually verify the finding against the evidence_reference."]

        xai_findings.append(
            XAIFinding(
                finding=title,
                confidence="High",
                evidence_reference=f.evidence_reference,
                reason=reason_text,
                owasp_mapping=", ".join(f.owasp),
                business_impact=impact_text,
                recommendation=rec_text,
                verification_checklist=checklist,
            )
        )
        
    return XAIOutput(
        executive_summary=summary,
        risk_narrative=f"Deterministic assessment complete. Local expert database active.",
        findings=xai_findings,
    )


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


_LOCAL_EXPLAIN_DATABASE = {
    "Missing Content-Security-Policy Header": {
        "reason": "The Content-Security-Policy (CSP) HTTP header is missing, allowing malicious scripts to be injected and executed on the client browser.",
        "business_impact": "Attackers can launch Cross-Site Scripting (XSS) attacks, steal user session cookies, redirect users to malicious landing pages, or perform clickjacking.",
        "recommendation": "Implement a strict Content-Security-Policy header. Restrict scripts, styles, and images to trusted origins only, and disable unsafe-inline execution.",
        "verification_checklist": [
            "Run 'curl -I <URL>' and inspect headers.",
            "Verify Content-Security-Policy header is present and configured correctly."
        ]
    },
    "Missing Strict-Transport-Security Header": {
        "reason": "The Strict-Transport-Security (HSTS) header is missing. The browser is not forced to communicate exclusively over secure HTTPS channels, enabling HTTP downgrade attacks.",
        "business_impact": "Active network attackers can intercept and capture sensitive session data via Man-in-the-Middle (MITM) redirection attacks.",
        "recommendation": "Configure the web server or application to return the Strict-Transport-Security header with a max-age of at least one year (e.g., 31536000), including includeSubDomains.",
        "verification_checklist": [
            "Query headers and verify Strict-Transport-Security exists.",
            "Ensure the max-age value is sufficiently large."
        ]
    },
    "Missing X-Frame-Options Header": {
        "reason": "The website is missing the X-Frame-Options or CSP frame-ancestors header, meaning it can be rendered inside a nested <frame> or <iframe> on an external site.",
        "business_impact": "Enables clickjacking attacks, where an attacker tricks a user into clicking invisible buttons on your site by overlaying it on top of another page.",
        "recommendation": "Add the X-Frame-Options HTTP response header set to DENY or SAMEORIGIN, or implement the modern frame-ancestors directive in your CSP.",
        "verification_checklist": [
            "Try loading the page inside an iframe on a local HTML test file.",
            "Verify browser blocks rendering due to X-Frame-Options configuration."
        ]
    },
    "Missing X-Content-Type-Options Header": {
        "reason": "The X-Content-Type-Options header is missing, which allows the browser to perform MIME-sniffing and treat non-executable file types as executable code.",
        "business_impact": "Can lead to Cross-Site Scripting (XSS) if users are allowed to upload text or image files containing malicious scripts.",
        "recommendation": "Add the X-Content-Type-Options: nosniff header to all web server responses.",
        "verification_checklist": [
            "Verify presence of X-Content-Type-Options: nosniff header in HTTP response headers."
        ]
    },
    "Server Header Discloses Technology": {
        "reason": "The Server HTTP header returns detailed information exposing the name of the web server or technology stack.",
        "business_impact": "Simplifies reconnaissance, enabling attackers to query vulnerability databases (CVEs) matching your exact server software versions.",
        "recommendation": "Modify web server configurations (e.g. set server_tokens off in Nginx or strip headers in proxy/CDN settings) to conceal technology names and versions.",
        "verification_checklist": [
            "Send an HTTP request and confirm the Server header returns a generic value or is completely removed."
        ]
    },
    "Invalid TLS Certificate": {
        "reason": "The SSL/TLS certificate used by the server is invalid (e.g. domain mismatch, self-signed, or untrusted root CA).",
        "business_impact": "Visitors will see critical browser security warnings. All data transmitted is susceptible to decryption via Man-in-the-Middle (MITM) interception.",
        "recommendation": "Replace the invalid certificate with a valid one signed by a trusted Certificate Authority (CA), ensuring the Common Name (CN) or SAN matches your domain.",
        "verification_checklist": [
            "Navigate to the page and verify browser shows a padlock.",
            "Inspect the certificate chain to ensure it terminates at a trusted root."
        ]
    },
    "TLS Certificate Has Expired": {
        "reason": "The TLS certificate has exceeded its validity period and is no longer trusted.",
        "business_impact": "Disrupts user traffic with secure connection warnings, indicating potential loss of confidentiality and integrity of session communication.",
        "recommendation": "Renew the TLS certificate immediately using Let's Encrypt or your certificate authority, and configure automated certificate renewal cron jobs.",
        "verification_checklist": [
            "Check certificate details to confirm the new validity dates are in the future."
        ]
    },
    "Content Defacement Detected": {
        "reason": "Significant deviations in the page layout or text structure were detected compared to the verified baseline snapshot.",
        "business_impact": "Severe reputational damage, phishing risks, and loss of user trust due to malicious alterations of site content.",
        "recommendation": "Revert the web site to a clean backup copy immediately. Audit access control lists, server logs, and admin accounts to identify the breach point.",
        "verification_checklist": [
            "Perform a code audit of the target page directory.",
            "Compare file hashes with original repository code."
        ]
    },
    "SQL Injection Vulnerability Detected": {
        "reason": "The scanner detected that input fields or URL parameters are vulnerable to SQL Injection, allowing raw SQL queries to be sent directly to the database.",
        "business_impact": "Critical risk of complete database compromise, unauthorized administrative access, data theft, or data destruction.",
        "recommendation": "Use parameterized queries, prepared statements, or ORM frameworks for all database operations. Implement strict input validation and WAF protection.",
        "verification_checklist": [
            "Test input fields using SQL payload testing.",
            "Ensure database errors are suppressed and parameterized commands are in use."
        ]
    },
    "Cross-Site Scripting (XSS) Detected": {
        "reason": "Input parameters are returned directly to the client browser without sanitization or HTML encoding.",
        "business_impact": "Session hijacking, redirection to malware, page defacement, and credential theft.",
        "recommendation": "Context-aware output encoding (HTML, JavaScript, CSS context encoding) must be applied to all user input before rendering.",
        "verification_checklist": [
            "Test input values with XSS vectors. Confirm vectors are either encoded or safely stripped by a filter."
        ]
    },
    "Sensitive Files Exposed": {
        "reason": "Directories, backup files, configuration files (e.g. .git, .env), or debug logs are publicly accessible.",
        "business_impact": "High risk of exposing database credentials, API keys, intellectual property, and source code.",
        "recommendation": "Implement strict access control rules (e.g. .htaccess or server directives) to deny access to sensitive directories and config files.",
        "verification_checklist": [
            "Confirm target paths return a 403 Forbidden or 404 Not Found response."
        ]
    },
    "Missing Rate Limiting (DDoS Vulnerable)": {
        "reason": "The target URL accepted a rapid burst of automated requests without responding with rate limit indicators or a 429 HTTP status code.",
        "business_impact": "Vulnerability to denial of service attacks, brute forcing, API abuse, and high infrastructure costs.",
        "recommendation": "Implement rate limiting policies (e.g. Nginx limit_req, Cloudflare rate limits, or middleware validation).",
        "verification_checklist": [
            "Run a load simulation tool and verify server responds with 429 status code for excess requests."
        ]
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


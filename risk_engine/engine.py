"""
risk_engine/engine.py — Deterministic Risk Assessment Engine.

Consumes a ScanEvidence object produced by the Evidence Engine.
Produces a fully populated RiskAssessment using ONLY the findings
embedded in that evidence.

STRICT RULES:
  - Never hardcodes any score value.
  - All penalties are read from risk_policy.json at runtime.
  - No AI. No narrative. No recommendations. Pure math.
  - Score starts at 100 and is decremented by policy-defined penalties.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime

from evidence_engine.models import ScanEvidence
from risk_engine.models import (
    AssessmentMetadata,
    AssessmentStatus,
    ConfidenceAssessment,
    FindingReference,
    FindingStatistics,
    OwaspSummary,
    RiskAssessment,
    RiskBreakdown,
    RiskSummary,
)


# ── Policy Loader ─────────────────────────────────────────────────────────────

_POLICY_PATH = os.path.join(
    os.path.dirname(__file__),
    "..", "evidence_engine", "risk_policy.json"
)


def _load_policy() -> dict:
    """
    Load risk_policy.json at call time.
    This ensures the policy is always fresh and never cached stale values.
    """
    policy_path = os.path.normpath(_POLICY_PATH)
    with open(policy_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ── Severity ordering ─────────────────────────────────────────────────────────

_SEVERITY_RANK = {
    "Critical":      5,
    "High":          4,
    "Medium":        3,
    "Low":           2,
    "Informational": 1,
}

_GRADE_MAP = [
    (90, "A+"),
    (80, "A"),
    (70, "B"),
    (55, "C"),
    (40, "D"),
    (0,  "F"),
]

_PRIORITY_MAP = [
    (80, "P5 — Informational"),
    (60, "P4 — Low"),
    (40, "P3 — Medium"),
    (20, "P2 — High"),
    (0,  "P1 — Critical"),
]


# ── Public Interface ──────────────────────────────────────────────────────────

def assess(evidence: ScanEvidence) -> RiskAssessment:
    """
    Convert a ScanEvidence object into a fully populated RiskAssessment.

    Pipeline:
        1. Load risk_policy.json
        2. Extract findings from ScanEvidence fields
        3. Apply policy penalties to each finding
        4. Compute overall score, grade, severity, priority
        5. Assemble and return RiskAssessment
    """
    policy = _load_policy()
    rules = policy.get("rules", {})

    # ── 1. Build FindingReferences from evidence ──────────────────────────────
    finding_refs: list[FindingReference] = []

    # 1a. Header-derived findings
    finding_refs.extend(_assess_headers(evidence, rules))

    # 1b. SSL-derived findings
    finding_refs.extend(_assess_ssl(evidence, rules))

    # 1c. Defacement / diff-derived findings
    finding_refs.extend(_assess_defacement(evidence, rules))
    
    # 1d. Active Scan findings
    finding_refs.extend(_assess_active_scan(evidence, rules))

    # ── 2. Compute scores ─────────────────────────────────────────────────────
    tech_findings = [f for f in finding_refs if "Cryptographic" not in " ".join(f.owasp)
                     and "defacement" not in f.evidence_reference.lower()]
    behavioral_findings = [f for f in finding_refs
                           if "defacement" in f.evidence_reference.lower()]

    overall_score, technical_score, behavioral_score = _compute_scores(
        finding_refs, tech_findings, behavioral_findings, rules
    )

    # ── 3. Grade / severity / priority ───────────────────────────────────────
    grade = _score_to_grade(overall_score)
    overall_severity = _highest_severity(finding_refs)
    priority = _score_to_priority(overall_score)

    # ── 4. Statistics ─────────────────────────────────────────────────────────
    stats = FindingStatistics(
        critical_count=    sum(1 for f in finding_refs if f.severity == "Critical"),
        high_count=        sum(1 for f in finding_refs if f.severity == "High"),
        medium_count=      sum(1 for f in finding_refs if f.severity == "Medium"),
        low_count=         sum(1 for f in finding_refs if f.severity == "Low"),
        informational_count=sum(1 for f in finding_refs if f.severity == "Informational"),
    )

    # ── 5. OWASP summary ──────────────────────────────────────────────────────
    all_owasp: list[str] = []
    for f in finding_refs:
        for o in f.owasp:
            if o not in all_owasp:
                all_owasp.append(o)

    # ── 6. Breakdown ──────────────────────────────────────────────────────────
    categories = list({f.category for f in finding_refs})
    components = _extract_affected_components(evidence)

    # ── 7. Confidence ─────────────────────────────────────────────────────────
    confidence, confidence_reason = _compute_confidence(evidence)

    # ── 8. Assessment hash (integrity) ───────────────────────────────────────
    hash_payload = (
        f"{evidence.metadata.url}|{overall_score}|{grade}|"
        f"{stats.critical_count}|{stats.high_count}|{evidence.metadata.timestamp}"
    )
    assessment_hash = hashlib.sha256(hash_payload.encode()).hexdigest()

    # ── 9. Assemble RiskAssessment ────────────────────────────────────────────
    return RiskAssessment(
        metadata=AssessmentMetadata(
            evidence_reference=evidence.metadata.scan_id or evidence.metadata.url,
            engine_version=policy.get("engine_version", "1.0"),
            policy_version=policy.get("policy_version", "1.0"),
            assessment_hash=assessment_hash,
        ),
        summary=RiskSummary(
            overall_security_score=overall_score,
            technical_score=technical_score,
            behavioral_integrity_score=behavioral_score,
            overall_grade=grade,
            overall_severity=overall_severity,
            overall_priority=priority,
        ),
        statistics=stats,
        breakdown=RiskBreakdown(
            categories=categories,
            affected_components=components,
        ),
        owasp=OwaspSummary(global_owasp_categories=all_owasp),
        confidence=ConfidenceAssessment(
            confidence_score=confidence,
            reason=confidence_reason,
        ),
        status=AssessmentStatus(
            status="COMPLETED",
            message=f"{len(finding_refs)} finding(s) evaluated against policy v{policy.get('policy_version', '1.0')}.",
        ),
        findings=finding_refs,
    )


# ── Evidence Assessors ────────────────────────────────────────────────────────

def _assess_headers(evidence: ScanEvidence, rules: dict) -> list[FindingReference]:
    """
    Derive FindingReferences from the security_headers evidence.
    Reads penalties exclusively from the policy rules dict.
    """
    refs: list[FindingReference] = []
    security_headers = evidence.headers.security_headers
    raw_headers_lower = {k.lower(): v for k, v in evidence.headers.headers.items()}

    # ── Missing required security headers ─────────────────────────────────────
    header_to_rule = {
        "content-security-policy":  ("missing_csp",                  "Content-Security-Policy"),
        "strict-transport-security": ("missing_hsts",                 "Strict-Transport-Security"),
        "x-frame-options":           ("missing_x_frame_options",      "X-Frame-Options"),
        "x-content-type-options":    ("missing_x_content_type_options","X-Content-Type-Options"),
    }

    for header_key, (rule_name, display_name) in header_to_rule.items():
        if header_key not in raw_headers_lower:
            rule = rules.get(rule_name, {})
            severity = rule.get("severity", "Low")
            owasp = rule.get("owasp", ["Security Misconfiguration"])
            refs.append(FindingReference(
                title=f"Missing {display_name} Header",
                severity=severity,
                category="HTTP Security Headers",
                owasp=owasp,
                evidence_reference=f"headers.security_headers['{header_key}'] = absent",
                confidence=100,
            ))

    # ── Information-leaking server header ─────────────────────────────────────
    if "server" in raw_headers_lower:
        rule = rules.get("server_header_exposure", {})
        severity = rule.get("severity", "Low")
        owasp = rule.get("owasp", ["Security Misconfiguration"])
        server_value = raw_headers_lower["server"]
        refs.append(FindingReference(
            title="Server Header Discloses Technology",
            severity=severity,
            category="Information Disclosure",
            owasp=owasp,
            evidence_reference=f"headers.headers['server'] = '{server_value}'",
            confidence=100,
        ))

    return refs


def _assess_ssl(evidence: ScanEvidence, rules: dict) -> list[FindingReference]:
    """Derive FindingReferences from TLS/SSL evidence."""
    refs: list[FindingReference] = []
    tls = evidence.ssl.tls_information
    cert = evidence.ssl.certificate_information

    if not tls and not cert:
        # HTTP target — no TLS evidence to assess
        return refs

    # ── Invalid / failed TLS ──────────────────────────────────────────────────
    if cert.get("valid") is False:
        rule = rules.get("invalid_ssl", {})
        refs.append(FindingReference(
            title="Invalid TLS Certificate",
            severity=rule.get("severity", "High"),
            category="Transport Security",
            owasp=rule.get("owasp", ["Cryptographic Failures"]),
            evidence_reference=f"ssl.certificate_information['valid'] = False",
            confidence=100,
        ))

    # ── Expired certificate ───────────────────────────────────────────────────
    days_left = cert.get("days_until_expiry")
    if days_left is not None and days_left < 0:
        rule = rules.get("expired_ssl", {})
        refs.append(FindingReference(
            title="TLS Certificate Has Expired",
            severity=rule.get("severity", "High"),
            category="Transport Security",
            owasp=rule.get("owasp", ["Cryptographic Failures"]),
            evidence_reference=f"ssl.certificate_information['days_until_expiry'] = {days_left}",
            confidence=100,
        ))
    elif days_left is not None and days_left <= 30:
        refs.append(FindingReference(
            title=f"TLS Certificate Expires in {days_left} Days",
            severity="Medium",
            category="Transport Security",
            owasp=["Cryptographic Failures"],
            evidence_reference=f"ssl.certificate_information['days_until_expiry'] = {days_left}",
            confidence=100,
        ))

    return refs


def _assess_defacement(evidence: ScanEvidence, rules: dict) -> list[FindingReference]:
    """Derive FindingReferences from diff/defacement evidence."""
    refs: list[FindingReference] = []
    change_type = evidence.diff.change_type
    metrics = evidence.metrics.raw_metrics

    defacement_detected = metrics.get("defacement_detected", False)
    similarity_score = metrics.get("similarity_score", None)

    if defacement_detected:
        rule = rules.get("defacement", {})
        evidence_ref = (
            f"diff.change_type = '{change_type}'"
            + (f", metrics.similarity_score = {similarity_score:.4f}" if similarity_score is not None else "")
        )
        refs.append(FindingReference(
            title="Content Defacement Detected",
            severity=rule.get("severity", "Critical"),
            category="Content Integrity",
            owasp=rule.get("owasp", ["Security Misconfiguration"]),
            evidence_reference=evidence_ref,
            confidence=95,
        ))

    return refs


def _assess_active_scan(evidence: ScanEvidence, rules: dict) -> list[FindingReference]:
    """Derive FindingReferences from active penetration testing payloads."""
    refs: list[FindingReference] = []
    
    if not hasattr(evidence, 'active_scan') or not evidence.active_scan:
        return refs
        
    active = evidence.active_scan
    
    if active.sqli_detected:
        rule = rules.get("sqli_detected", {})
        refs.append(FindingReference(
            title="SQL Injection Vulnerability Detected",
            severity=rule.get("severity", "Critical"),
            category="Active Exploitation",
            owasp=rule.get("owasp", ["Injection"]),
            evidence_reference="active_scan.sqli_detected = True",
            confidence=100,
        ))
        
    if active.xss_detected:
        rule = rules.get("xss_detected", {})
        refs.append(FindingReference(
            title="Cross-Site Scripting (XSS) Detected",
            severity=rule.get("severity", "High"),
            category="Active Exploitation",
            owasp=rule.get("owasp", ["Injection"]),
            evidence_reference="active_scan.xss_detected = True",
            confidence=100,
        ))
        
    if active.sensitive_files_exposed:
        rule = rules.get("sensitive_file_exposed", {})
        refs.append(FindingReference(
            title="Sensitive Files Exposed",
            severity=rule.get("severity", "Critical"),
            category="Active Exploitation",
            owasp=rule.get("owasp", ["Security Misconfiguration", "Sensitive Data Exposure"]),
            evidence_reference=f"active_scan.sensitive_files_exposed = {active.sensitive_files_exposed}",
            confidence=100,
        ))
        
    if not active.rate_limiting_active:
        rule = rules.get("missing_rate_limit", {})
        refs.append(FindingReference(
            title="Missing Rate Limiting (DDoS Vulnerable)",
            severity=rule.get("severity", "Medium"),
            category="Active Exploitation",
            owasp=rule.get("owasp", ["Security Misconfiguration"]),
            evidence_reference="active_scan.rate_limiting_active = False",
            confidence=95,
        ))
        
    return refs


# ── Score Computation ─────────────────────────────────────────────────────────

def _compute_scores(
    all_findings: list[FindingReference],
    tech_findings: list[FindingReference],
    behavioral_findings: list[FindingReference],
    rules: dict,
) -> tuple[int, int, int]:
    """
    Compute overall, technical, and behavioral scores.
    All penalties come from risk_policy.json — never hardcoded.
    Score starts at 100 and decrements per finding.
    """
    def _penalty_for(finding: FindingReference) -> int:
        """Look up the policy penalty for a finding by its title."""
        title = finding.title.lower()
        key = None
        if "content-security-policy" in title: key = "missing_csp"
        elif "strict-transport-security" in title: key = "missing_hsts"
        elif "x-frame-options" in title: key = "missing_x_frame_options"
        elif "x-content-type-options" in title: key = "missing_x_content_type_options"
        elif "server header" in title: key = "server_header_exposure"
        elif "invalid" in title and "ssl" in title: key = "invalid_ssl"
        elif "expired" in title and "ssl" in title: key = "expired_ssl"
        elif "defacement" in title: key = "defacement"

        if key and key in rules:
            return rules[key].get("score_penalty", 0)

        # Fallback: severity-based floor if no matching rule found
        return {"Critical": 40, "High": 20, "Medium": 10, "Low": 5, "Informational": 0}.get(finding.severity, 0)

    def _score_from(findings: list[FindingReference]) -> int:
        penalty = sum(_penalty_for(f) for f in findings)
        return max(0, 100 - penalty)

    overall = _score_from(all_findings)
    technical = _score_from(tech_findings)
    behavioral = _score_from(behavioral_findings)

    return overall, technical, behavioral


# ── Helpers ───────────────────────────────────────────────────────────────────

def _score_to_grade(score: int) -> str:
    for threshold, grade in _GRADE_MAP:
        if score >= threshold:
            return grade
    return "F"


def _score_to_priority(score: int) -> str:
    for threshold, priority in _PRIORITY_MAP:
        if score > threshold:
            return priority
    return "P1 — Critical"


def _highest_severity(findings: list[FindingReference]) -> str:
    if not findings:
        return "Informational"
    return max(findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 0)).severity


def _compute_confidence(evidence: ScanEvidence) -> tuple[int, str]:
    """
    Compute confidence percentage based on completeness of evidence.
    Deducts points for each unavailable evidence source.
    """
    score = 100
    reasons: list[str] = []

    if not evidence.headers.headers:
        score -= 30
        reasons.append("HTTP headers unavailable")

    if not evidence.ssl.tls_information and not evidence.ssl.certificate_information:
        score -= 15
        reasons.append("TLS evidence unavailable (HTTP target or SSL failed)")

    metrics = evidence.metrics.raw_metrics
    if "defacement_detected" not in metrics:
        score -= 20
        reasons.append("Snapshot/diff evidence unavailable")

    confidence_score = max(0, score)
    reason = "Evidence complete" if not reasons else "Partial evidence: " + "; ".join(reasons)
    return confidence_score, reason


def _extract_affected_components(evidence: ScanEvidence) -> list[str]:
    """Derive a list of affected infrastructure components from evidence."""
    components: list[str] = []

    if evidence.headers.headers:
        components.append("Web Server")

    tls_info = evidence.ssl.tls_information
    if tls_info:
        components.append("TLS Layer")

    metrics = evidence.metrics.raw_metrics
    if metrics.get("defacement_detected"):
        components.append("HTML Content")

    if evidence.metadata.resolved_ip:
        components.append(f"Endpoint ({evidence.metadata.resolved_ip})")

    return components

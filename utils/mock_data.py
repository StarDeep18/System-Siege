"""
utils/mock_data.py — Static mock data for UI development.
Replace with live Firebase / Evidence Engine data in production.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone


# ── Helpers ───────────────────────────────────────────────────────────────────

def _dt(days_ago: int = 0, hours_ago: int = 0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago)


# ── KPI Summary ───────────────────────────────────────────────────────────────

KPI_DATA = {
    "security_score":    74,
    "score_change":      -6,
    "threat_level":      "MEDIUM",
    "protected_assets":  6,
    "critical_alerts":   3,
    "new_alerts":        2,
    "todays_scans":      7,
}

# ── Assets ────────────────────────────────────────────────────────────────────

MOCK_ASSETS = [
    {
        "id": "a1", "name": "Main Website", "url": "https://example.com",
        "status": "active", "risk_score": 82, "risk_level": "low",
        "last_scanned": _dt(0, 2), "defacement_detected": False,
        "vulns": 2, "added": _dt(30),
    },
    {
        "id": "a2", "name": "Admin Portal", "url": "https://admin.example.com",
        "status": "critical", "risk_score": 34, "risk_level": "critical",
        "last_scanned": _dt(1), "defacement_detected": True,
        "vulns": 8, "added": _dt(45),
    },
    {
        "id": "a3", "name": "API Gateway", "url": "https://api.example.com",
        "status": "warning", "risk_score": 61, "risk_level": "medium",
        "last_scanned": _dt(0, 6), "defacement_detected": False,
        "vulns": 4, "added": _dt(60),
    },
    {
        "id": "a4", "name": "Customer Portal", "url": "https://portal.example.com",
        "status": "active", "risk_score": 78, "risk_level": "low",
        "last_scanned": _dt(2), "defacement_detected": False,
        "vulns": 3, "added": _dt(20),
    },
    {
        "id": "a5", "name": "Dev Environment", "url": "https://dev.example.com",
        "status": "warning", "risk_score": 55, "risk_level": "high",
        "last_scanned": _dt(3), "defacement_detected": False,
        "vulns": 5, "added": _dt(14),
    },
    {
        "id": "a6", "name": "Corporate Blog", "url": "https://blog.example.com",
        "status": "active", "risk_score": 90, "risk_level": "low",
        "last_scanned": _dt(0, 4), "defacement_detected": False,
        "vulns": 1, "added": _dt(90),
    },
]

# ── Scans ─────────────────────────────────────────────────────────────────────

MOCK_SCANS = [
    {
        "id": "s1", "asset_name": "Main Website", "url": "https://example.com",
        "timestamp": _dt(0, 1), "risk_score": 82, "risk_level": "low",
        "defacement_detected": False, "vulns_count": 2, "status": "completed",
        "tls_valid": True, "https": True,
    },
    {
        "id": "s2", "asset_name": "Admin Portal", "url": "https://admin.example.com",
        "timestamp": _dt(1), "risk_score": 34, "risk_level": "critical",
        "defacement_detected": True, "vulns_count": 8, "status": "alert",
        "tls_valid": False, "https": True,
    },
    {
        "id": "s3", "asset_name": "API Gateway", "url": "https://api.example.com",
        "timestamp": _dt(0, 6), "risk_score": 61, "risk_level": "medium",
        "defacement_detected": False, "vulns_count": 4, "status": "completed",
        "tls_valid": True, "https": True,
    },
    {
        "id": "s4", "asset_name": "Customer Portal", "url": "https://portal.example.com",
        "timestamp": _dt(2), "risk_score": 78, "risk_level": "low",
        "defacement_detected": False, "vulns_count": 3, "status": "completed",
        "tls_valid": True, "https": True,
    },
    {
        "id": "s5", "asset_name": "Dev Environment", "url": "https://dev.example.com",
        "timestamp": _dt(3), "risk_score": 55, "risk_level": "high",
        "defacement_detected": False, "vulns_count": 5, "status": "warning",
        "tls_valid": True, "https": False,
    },
    {
        "id": "s6", "asset_name": "Corporate Blog", "url": "https://blog.example.com",
        "timestamp": _dt(0, 4), "risk_score": 90, "risk_level": "low",
        "defacement_detected": False, "vulns_count": 1, "status": "completed",
        "tls_valid": True, "https": True,
    },
    {
        "id": "s7", "asset_name": "Main Website", "url": "https://example.com",
        "timestamp": _dt(4), "risk_score": 80, "risk_level": "low",
        "defacement_detected": False, "vulns_count": 2, "status": "completed",
        "tls_valid": True, "https": True,
    },
]

# ── Vulnerabilities ───────────────────────────────────────────────────────────

MOCK_VULNERABILITIES = [
    {
        "title": "Content Defacement Detected",
        "severity": "critical", "owasp": "A08:2021",
        "asset": "Admin Portal", "evidence": "Similarity score: 0.18 (threshold: 0.30)",
        "recommendation": "Restore from clean backup immediately. Investigate access logs.",
    },
    {
        "title": "Missing Content-Security-Policy",
        "severity": "high", "owasp": "A05:2021",
        "asset": "Admin Portal", "evidence": "Header absent from HTTP response",
        "recommendation": "Add CSP header restricting script sources to trusted origins.",
    },
    {
        "title": "SSL Certificate Expires in 12 Days",
        "severity": "high", "owasp": "A02:2021",
        "asset": "Main Website", "evidence": "Not-After: in 12 days",
        "recommendation": "Renew TLS certificate before expiry to prevent service disruption.",
    },
    {
        "title": "Missing HSTS Header",
        "severity": "high", "owasp": "A05:2021",
        "asset": "API Gateway", "evidence": "Strict-Transport-Security header absent",
        "recommendation": "Enable HSTS with min-age=31536000 and includeSubDomains.",
    },
    {
        "title": "Server Version Disclosure",
        "severity": "medium", "owasp": "A05:2021",
        "asset": "Admin Portal", "evidence": "Server: Apache/2.4.51 (Ubuntu)",
        "recommendation": "Configure ServerTokens Prod in Apache to suppress version info.",
    },
    {
        "title": "Missing X-Frame-Options",
        "severity": "medium", "owasp": "A05:2021",
        "asset": "Dev Environment", "evidence": "X-Frame-Options header absent",
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN header.",
    },
    {
        "title": "HTTP Available (Non-HTTPS)",
        "severity": "high", "owasp": "A02:2021",
        "asset": "Dev Environment", "evidence": "Scheme: http://",
        "recommendation": "Force HTTPS redirect and disable HTTP entirely.",
    },
    {
        "title": "Missing Referrer-Policy",
        "severity": "low", "owasp": "A05:2021",
        "asset": "Customer Portal", "evidence": "Referrer-Policy header absent",
        "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin.",
    },
]

# ── Reports ───────────────────────────────────────────────────────────────────

MOCK_REPORTS = [
    {
        "id": "r1", "title": "Admin Portal — Critical Incident",
        "asset": "Admin Portal", "generated_at": _dt(1),
        "risk_level": "critical", "risk_score": 34,
        "findings_count": 8, "defacement": True,
        "summary": "Critical: Content defacement detected with similarity score 0.18. TLS issues and 7 additional security misconfigurations identified. Immediate remediation required.",
        "executive_summary": "The Admin Portal has been compromised. Defacement was detected with high confidence (82%). Attackers likely exploited missing CSP header to inject malicious content. Immediate action required.",
    },
    {
        "id": "r2", "title": "API Gateway — Security Assessment",
        "asset": "API Gateway", "generated_at": _dt(3),
        "risk_level": "medium", "risk_score": 61,
        "findings_count": 4, "defacement": False,
        "summary": "4 security misconfigurations found. No defacement detected. HSTS and CSP headers missing.",
        "executive_summary": "The API Gateway has acceptable security posture but requires header hardening. Missing HSTS exposes users to SSL stripping attacks.",
    },
    {
        "id": "r3", "title": "Main Website — Routine Audit",
        "asset": "Main Website", "generated_at": _dt(5),
        "risk_level": "low", "risk_score": 82,
        "findings_count": 2, "defacement": False,
        "summary": "2 minor issues: expiring TLS certificate (12 days) and missing Permissions-Policy header.",
        "executive_summary": "Main website maintains strong security posture. Certificate renewal is time-sensitive and should be prioritised.",
    },
    {
        "id": "r4", "title": "Dev Environment — Security Review",
        "asset": "Dev Environment", "generated_at": _dt(7),
        "risk_level": "high", "risk_score": 55,
        "findings_count": 5, "defacement": False,
        "summary": "HTTP-only access, missing X-Frame-Options, server version disclosure.",
        "executive_summary": "Dev environment has significant security gaps including unencrypted HTTP transport. Should be isolated from production network.",
    },
]

# ── Audit Logs ────────────────────────────────────────────────────────────────

MOCK_AUDIT_LOGS = [
    {"id": "l01", "user": "admin@sentinel.ai", "action": "SCAN_INITIATED", "target": "https://example.com", "timestamp": _dt(0, 1), "ip": "192.168.1.10", "status": "success"},
    {"id": "l02", "user": "analyst@sentinel.ai", "action": "ASSET_ADDED", "target": "https://api.example.com", "timestamp": _dt(0, 3), "ip": "192.168.1.22", "status": "success"},
    {"id": "l03", "user": "admin@sentinel.ai", "action": "SCAN_INITIATED", "target": "https://admin.example.com", "timestamp": _dt(1), "ip": "192.168.1.10", "status": "alert"},
    {"id": "l04", "user": "analyst@sentinel.ai", "action": "REPORT_GENERATED", "target": "Admin Portal Incident Report", "timestamp": _dt(1, 2), "ip": "192.168.1.22", "status": "success"},
    {"id": "l05", "user": "admin@sentinel.ai", "action": "USER_LOGIN", "target": "admin@sentinel.ai", "timestamp": _dt(2), "ip": "203.0.113.45", "status": "success"},
    {"id": "l06", "user": "unknown", "action": "LOGIN_FAILED", "target": "admin@sentinel.ai", "timestamp": _dt(2, 1), "ip": "198.51.100.7", "status": "failed"},
    {"id": "l07", "user": "analyst@sentinel.ai", "action": "SCAN_INITIATED", "target": "https://blog.example.com", "timestamp": _dt(3), "ip": "192.168.1.22", "status": "success"},
    {"id": "l08", "user": "admin@sentinel.ai", "action": "ASSET_DELETED", "target": "https://old-staging.example.com", "timestamp": _dt(4), "ip": "192.168.1.10", "status": "success"},
    {"id": "l09", "user": "admin@sentinel.ai", "action": "ROLE_CHANGED", "target": "analyst@sentinel.ai → admin", "timestamp": _dt(5), "ip": "192.168.1.10", "status": "success"},
    {"id": "l10", "user": "analyst@sentinel.ai", "action": "SCAN_INITIATED", "target": "https://portal.example.com", "timestamp": _dt(6), "ip": "192.168.1.22", "status": "success"},
    {"id": "l11", "user": "admin@sentinel.ai", "action": "REPORT_EXPORTED", "target": "r3_main_website.pdf", "timestamp": _dt(7), "ip": "192.168.1.10", "status": "success"},
    {"id": "l12", "user": "unknown", "action": "LOGIN_FAILED", "target": "root@sentinel.ai", "timestamp": _dt(7, 3), "ip": "45.33.32.156", "status": "failed"},
]

# ── Timeline Data ─────────────────────────────────────────────────────────────

def get_threat_timeline():
    """Return 30 days of scan dates and risk scores for the timeline chart."""
    random.seed(42)
    dates = [datetime.now(timezone.utc) - timedelta(days=i) for i in range(29, -1, -1)]
    base_scores = [random.randint(65, 92) for _ in range(30)]
    # Simulate incident around day 10–13 (index 17–20 from oldest)
    base_scores[17] = 48
    base_scores[18] = 32
    base_scores[19] = 28
    base_scores[20] = 41
    base_scores[21] = 55
    # Recent dip
    base_scores[27] = 70
    base_scores[28] = 68
    base_scores[29] = 74
    return dates, base_scores


def get_score_trend():
    """Return 7-day daily scores for trend chart."""
    random.seed(7)
    dates = [datetime.now(timezone.utc) - timedelta(days=i) for i in range(6, -1, -1)]
    scores = [79, 76, 72, 68, 71, 74, 74]
    return dates, scores


def get_risk_distribution():
    """Return counts by risk level for distribution chart."""
    return {"Critical": 1, "High": 2, "Medium": 2, "Low": 2}


def get_vuln_by_category():
    """Return vulnerability counts by OWASP category."""
    return {
        "A05 – Misconfiguration": 5,
        "A02 – Crypto Failures": 2,
        "A08 – Data Integrity": 1,
    }

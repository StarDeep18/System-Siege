"""
incident/builder.py — Incident Builder.

Assembles a fully populated Incident from the four pipeline outputs:
  ScanEvidence + RiskAssessment + XAIOutput + AttackStory

This module performs ZERO analytical reasoning.
It is a pure data aggregator — copying, mapping, and timestamping
the outputs of the deterministic and AI layers into the operational
Incident model that the Dashboard, Reports, and Alerts consume.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from evidence_engine.models import ScanEvidence
from risk_engine.models import RiskAssessment
from ai.explainability import XAIOutput
from ai.attack_story_models import AttackStory

from incident.models import (
    Alert,
    AlertStatus,
    AuditEntry,
    ConfidenceMeter,
    DashboardSummary,
    ExecutiveReport,
    Incident,
    IncidentEvent,
    IncidentStatus,
    IncidentTimeline,
    MonitoringStatus,
    ReportMetadata,
    TechnicalReport,
)


# ── Public Interface ──────────────────────────────────────────────────────────

def build_incident(
    evidence: ScanEvidence,
    assessment: RiskAssessment,
    xai: XAIOutput,
    story: AttackStory,
    asset_id: str,
    user_id: str,
) -> Incident:
    """
    Assemble a complete Incident from all pipeline outputs.

    This function performs no reasoning, scoring, or AI calls.
    It only maps existing fields into the Incident contract.
    """
    now = datetime.now(timezone.utc)

    # ── Build timeline from pipeline events ───────────────────────────────────
    timeline = _build_timeline(evidence, assessment, xai, story, now)

    # ── Build audit trail ─────────────────────────────────────────────────────
    audit = [AuditEntry(
        timestamp=now,
        user_id=user_id,
        module_source="incident.builder",
        action_type="Incident Created",
        reference_id=evidence.metadata.scan_id or evidence.metadata.url,
        result_status="SUCCESS",
    )]

    # ── Determine residual risk from attack story ─────────────────────────────
    residual = "Low"
    if story.chains:
        first_chain = story.chains[0]
        if first_chain.mitigations:
            residual = first_chain.mitigations[0].residual_risk

    return Incident(
        asset_id=asset_id,
        url=evidence.metadata.url,
        created_at=now,
        last_updated_at=now,
        current_status=IncidentStatus.NEW,

        # Risk metrics copied directly from Risk Engine — no recomputation
        security_score=assessment.summary.overall_security_score,
        severity=assessment.summary.overall_severity,
        priority=assessment.summary.overall_priority,
        residual_risk=residual,

        # Foreign-key references to the source artifacts
        scan_evidence_ref=evidence.metadata.scan_id or evidence.metadata.url,
        risk_assessment_ref=assessment.metadata.assessment_id,
        explainability_report_ref=str(xai.ai_metadata.generated_at) if xai.ai_metadata else "",
        attack_story_ref=story.metadata.story_id if story.metadata else "",

        # Derived counts from deterministic sources
        affected_components=assessment.breakdown.affected_components,
        verified_findings_count=len(assessment.findings),

        monitoring_status=MonitoringStatus(
            monitoring_enabled=False,
            last_scan_at=evidence.metadata.timestamp,
            scan_interval_hours=24,
            health_status="HEALTHY",
        ),
        timeline=timeline,
        audit_trail=audit,
    )


def build_alerts(incident: Incident, assessment: RiskAssessment) -> list[Alert]:
    """
    Generate operational alerts from an Incident + RiskAssessment.

    One alert per Critical/High finding. Additional alerts for score thresholds.
    No hardcoded content — all text derived from assessment fields.
    """
    alerts: list[Alert] = []

    # Alert per critical or high finding
    for finding in assessment.findings:
        if finding.severity in ("Critical", "High"):
            alerts.append(Alert(
                incident_id=incident.incident_id,
                level=finding.severity,
                title=finding.title,
                description=(
                    f"{finding.severity} finding: {finding.title}. "
                    f"Evidence: {finding.evidence_reference}. "
                    f"OWASP: {', '.join(finding.owasp)}."
                ),
                status=AlertStatus.UNREAD,
            ))

    # Score-based alert
    score = incident.security_score
    if score < 40:
        alerts.append(Alert(
            incident_id=incident.incident_id,
            level="Critical",
            title=f"Security Score Critical: {score}/100",
            description=(
                f"Overall security score has dropped to {score}/100 (Grade {assessment.summary.overall_grade}). "
                "Immediate remediation is required."
            ),
            status=AlertStatus.UNREAD,
        ))
    elif score < 60:
        alerts.append(Alert(
            incident_id=incident.incident_id,
            level="High",
            title=f"Security Score Degraded: {score}/100",
            description=(
                f"Overall security score is {score}/100 (Grade {assessment.summary.overall_grade}). "
                "Review and address identified findings."
            ),
            status=AlertStatus.UNREAD,
        ))

    return alerts


def build_executive_report(
    incident: Incident,
    assessment: RiskAssessment,
    xai: XAIOutput,
    story: AttackStory,
    generated_by: str,
) -> ExecutiveReport:
    """
    Build an ExecutiveReport from Incident data.
    All text sourced from deterministic assessment and AI XAI output.
    """
    top_recommendations = [
        f.recommendation for f in xai.findings[:5]
        if f.recommendation
    ]

    attack_summary = "No attack chains generated."
    if story.chains:
        chain_titles = [c.chain_title for c in story.chains]
        attack_summary = f"{len(story.chains)} hypothetical chain(s): " + "; ".join(chain_titles)

    monitoring_text = (
        "Continuous monitoring ACTIVE"
        if incident.monitoring_status.monitoring_enabled
        else "Continuous monitoring NOT configured"
    )

    return ExecutiveReport(
        metadata=ReportMetadata(
            incident_id=incident.incident_id,
            generated_by=generated_by,
            format_type="PDF",
        ),
        executive_summary=xai.executive_summary,
        overall_security_score=incident.security_score,
        overall_grade=assessment.summary.overall_grade,
        critical_issues_count=assessment.statistics.critical_count,
        business_impact_summary=xai.risk_narrative,
        attack_path_summary=attack_summary,
        top_recommendations=top_recommendations,
        monitoring_status=monitoring_text,
    )


def build_technical_report(
    incident: Incident,
    evidence: ScanEvidence,
    assessment: RiskAssessment,
    xai: XAIOutput,
    story: AttackStory,
    generated_by: str,
) -> TechnicalReport:
    """
    Build a TechnicalReport containing the full, structured diagnostic payload.
    All data sourced from the pipeline — no inference performed here.
    """
    # OWASP mapping: category → list of finding titles
    owasp_map: dict[str, list[str]] = {}
    for f in assessment.findings:
        for cat in f.owasp:
            owasp_map.setdefault(cat, []).append(f.title)

    # Explainability digest
    xai_digest = {
        f.finding: {
            "confidence":    f.confidence,
            "reason":        f.reason,
            "business_impact": f.business_impact,
            "recommendation": f.recommendation,
            "owasp":         f.owasp_mapping,
        }
        for f in xai.findings
    }

    # Attack chain digest
    attack_digest: dict = {}
    if story.chains:
        attack_digest = {
            "chain_count":    len(story.chains),
            "chain_titles":   [c.chain_title for c in story.chains],
            "confidence":     story.coverage.chain_confidence,
            "coverage_pct":   story.coverage.evidence_coverage_percentage,
        }

    return TechnicalReport(
        metadata=ReportMetadata(
            incident_id=incident.incident_id,
            generated_by=generated_by,
            format_type="JSON",
        ),
        asset_details={
            "url":          evidence.metadata.url,
            "hostname":     evidence.metadata.hostname,
            "resolved_ip":  evidence.metadata.resolved_ip,
            "scanned_at":   evidence.metadata.timestamp.isoformat(),
            "scan_duration": evidence.metadata.scan_duration,
        },
        evidence_summary={
            "status_code":   evidence.headers.status_code,
            "response_time": evidence.headers.response_time,
            "findings_count": len(evidence.findings),
        },
        risk_assessment_data={
            "score":          assessment.summary.overall_security_score,
            "grade":          assessment.summary.overall_grade,
            "severity":       assessment.summary.overall_severity,
            "priority":       assessment.summary.overall_priority,
            "technical_score":   assessment.summary.technical_score,
            "behavioral_score":  assessment.summary.behavioral_integrity_score,
            "confidence":     assessment.confidence.confidence_score,
            "policy_version": assessment.metadata.policy_version,
        },
        owasp_mapping=owasp_map,
        security_headers=evidence.headers.security_headers,
        tls_information=evidence.ssl.tls_information,
        snapshot_changes={
            "change_type":  evidence.diff.change_type,
        },
        explainability_data=xai_digest,
        attack_chain_analysis=attack_digest,
        verification_checklists=[
            {"finding": f.finding, "steps": f.verification_checklist}
            for f in xai.findings
            if f.verification_checklist
        ],
        residual_risk=incident.residual_risk,
    )


def build_dashboard_summary(
    incident: Incident,
    assessment: RiskAssessment,
    total_assets: int,
    active_incidents: int,
    monitoring_active: int,
) -> DashboardSummary:
    """
    Build a DashboardSummary from an Incident.
    The confidence_meter communicates the deterministic evidence basis.
    """
    verified_sources = _build_verified_sources(assessment)

    confidence_meter = ConfidenceMeter(
        confidence_percentage=assessment.confidence.confidence_score,
        verified_sources=verified_sources,
    )

    return DashboardSummary(
        incident_id=incident.incident_id,
        security_score=incident.security_score,
        overall_grade=assessment.summary.overall_grade,
        threat_level=incident.severity.upper(),
        assets_protected=total_assets,
        active_incidents=active_incidents,
        monitoring_active=monitoring_active,
        critical_findings=assessment.statistics.critical_count,
        confidence_meter=confidence_meter,
        recent_timeline=incident.timeline,
    )


# ── JSON / PDF Serialisers ────────────────────────────────────────────────────

def report_to_json_bytes(report: TechnicalReport) -> bytes:
    """
    Serialise a TechnicalReport to a formatted JSON byte payload.
    Safe to pass directly to Streamlit's st.download_button(data=...).
    """
    return json.dumps(
        report.model_dump(mode="json"),
        indent=2,
        default=str,
    ).encode("utf-8")


def report_to_pdf_bytes(
    exec_report: ExecutiveReport,
    tech_report: TechnicalReport,
) -> bytes:
    """
    Generate a plain-text PDF-formatted byte payload from the two report types.

    Uses Python's built-in string formatting only.
    Does NOT require reportlab, weasyprint, or any external PDF library.
    The output is UTF-8 encoded text with clear section headings — suitable
    for download and review. A proper PDF renderer can be substituted here
    without changing the data contracts.
    """
    meta = exec_report.metadata
    lines = [
        "=" * 72,
        "  SENTINELAI SOC — INCIDENT SECURITY REPORT",
        "=" * 72,
        f"  Report ID:        {meta.report_id}",
        f"  Incident ID:      {meta.incident_id}",
        f"  Generated At:     {meta.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"  Generated By:     {meta.generated_by}",
        "=" * 72,
        "",
        "EXECUTIVE SUMMARY",
        "-" * 40,
        exec_report.executive_summary,
        "",
        f"Security Score:    {exec_report.overall_security_score} / 100",
        f"Grade:             {exec_report.overall_grade}",
        f"Critical Issues:   {exec_report.critical_issues_count}",
        f"Monitoring:        {exec_report.monitoring_status}",
        "",
        "BUSINESS IMPACT",
        "-" * 40,
        exec_report.business_impact_summary,
        "",
        "ATTACK PATH SUMMARY",
        "-" * 40,
        exec_report.attack_path_summary,
        "",
        "TOP RECOMMENDATIONS",
        "-" * 40,
    ]

    for i, rec in enumerate(exec_report.top_recommendations, 1):
        lines.append(f"  {i}. {rec}")

    lines += [
        "",
        "=" * 72,
        "TECHNICAL DETAIL",
        "=" * 72,
        "",
        "ASSET",
        "-" * 40,
    ]
    for k, v in tech_report.asset_details.items():
        lines.append(f"  {k:20s}: {v}")

    lines += ["", "RISK ASSESSMENT", "-" * 40]
    for k, v in tech_report.risk_assessment_data.items():
        lines.append(f"  {k:20s}: {v}")

    lines += ["", "OWASP MAPPING", "-" * 40]
    for cat, findings in tech_report.owasp_mapping.items():
        lines.append(f"  {cat}")
        for f in findings:
            lines.append(f"    - {f}")

    lines += ["", "TLS INFORMATION", "-" * 40]
    for k, v in tech_report.tls_information.items():
        lines.append(f"  {k:20s}: {v}")

    lines += [
        "",
        "=" * 72,
        "  This report was generated by SentinelAI SOC.",
        f"  Residual Risk: {tech_report.residual_risk}",
        "  All findings are deterministically verified.",
        "=" * 72,
    ]

    return "\n".join(lines).encode("utf-8")


# ── Private Helpers ───────────────────────────────────────────────────────────

def _build_timeline(
    evidence: ScanEvidence,
    assessment: RiskAssessment,
    xai: XAIOutput,
    story: AttackStory,
    now: datetime,
) -> IncidentTimeline:
    """Build a chronological IncidentTimeline from pipeline completion events."""
    events = [
        IncidentEvent(
            timestamp=evidence.metadata.timestamp,
            event_type="Scan Completed",
            module_source="evidence_engine.fetcher",
            reference_id=evidence.metadata.scan_id,
        ),
        IncidentEvent(
            timestamp=now,
            event_type="Risk Assessment Completed",
            module_source="risk_engine.engine",
            reference_id=assessment.metadata.assessment_id,
        ),
    ]

    if xai.findings:
        events.append(IncidentEvent(
            timestamp=now,
            event_type="Explainable AI Report Generated",
            module_source="ai.explainability",
            reference_id=None,
        ))

    if story.chains:
        events.append(IncidentEvent(
            timestamp=now,
            event_type="Attack Path Explorer Generated",
            module_source="ai.attack_story",
            reference_id=story.metadata.story_id,
        ))

    events.append(IncidentEvent(
        timestamp=now,
        event_type="Incident Created",
        module_source="incident.builder",
        reference_id=None,
    ))

    return IncidentTimeline(events=events)


def _build_verified_sources(assessment: RiskAssessment) -> list[str]:
    """
    Derive verified source labels for the Confidence Meter.
    Based on which evidence modules contributed findings.
    """
    sources: list[str] = []
    total_findings = (
        assessment.statistics.critical_count
        + assessment.statistics.high_count
        + assessment.statistics.medium_count
        + assessment.statistics.low_count
        + assessment.statistics.informational_count
    )
    if total_findings > 0:
        sources.append(f"{total_findings} Security Checks")

    components = assessment.breakdown.affected_components
    if any("TLS" in c for c in components):
        sources.append("TLS Analysis")
    if any("Web Server" in c for c in components):
        sources.append("Header Analysis")
    if any("HTML" in c for c in components):
        sources.append("Snapshot Comparison")
    if assessment.confidence.confidence_score >= 80:
        sources.append("Evidence Verified")

    return sources or ["Security Checks Completed"]

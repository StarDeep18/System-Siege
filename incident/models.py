"""
incident/models.py — Strongly typed operational data contracts for the SOC.

This module defines the single source of truth for the Security Operations Center.
These objects aggregate intelligence from the Evidence Engine, Risk Engine, 
and AI layers into actionable operational entities (Incidents, Alerts, Reports) 
without performing any analytical reasoning themselves.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Dict, Any
import uuid
from enum import Enum

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────────

class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    MITIGATED = "MITIGATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AlertStatus(str, Enum):
    UNREAD = "UNREAD"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    DISMISSED = "DISMISSED"


# ── Audit & Timeline Models ───────────────────────────────────────────────────

class AuditEntry(BaseModel):
    """Immutable audit trail of actions taken on the platform."""
    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: str = Field(..., description="ID of the user who performed the action")
    module_source: str = Field(..., description="The module that triggered the action (e.g., 'auth', 'risk_engine')")
    action_type: str = Field(..., description="e.g., 'Scan Completed', 'Incident Status Changed'")
    reference_id: str = Field(..., description="ID of the related resource (e.g., scan_id, incident_id)")
    result_status: str = Field("SUCCESS", description="SUCCESS, FAILURE")


class IncidentEvent(BaseModel):
    """A distinct occurrence in the lifecycle of an incident."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str = Field(..., description="e.g., 'Critical Alert Generated', 'Attack Path Generated'")
    module_source: str = Field(..., description="e.g., 'Alert Engine', 'Explainable AI'")
    reference_id: Optional[str] = Field(None, description="Optional ID pointing to a specific artifact (like an alert_id)")


class IncidentTimeline(BaseModel):
    """Chronological progression of an incident."""
    events: List[IncidentEvent] = Field(default_factory=list)


class MonitoringStatus(BaseModel):
    """State of ongoing continuous monitoring."""
    monitoring_enabled: bool = Field(False)
    last_scan_at: Optional[datetime] = Field(None)
    next_scheduled_scan_at: Optional[datetime] = Field(None)
    scan_interval_hours: int = Field(24)
    health_status: str = Field("HEALTHY", description="HEALTHY, DEGRADED, FAILING")


# ── Alert Models ──────────────────────────────────────────────────────────────

class Alert(BaseModel):
    """An actionable notification derived from an Incident."""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = Field(..., description="The parent incident this alert relates to")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    level: str = Field(..., description="Critical, High, Medium, Low, Informational")
    title: str = Field(..., description="Headline of the alert (e.g., 'Security Score Decreased')")
    description: str = Field(...)
    status: AlertStatus = Field(AlertStatus.UNREAD)


# ── Incident Model (Single Source of Truth) ───────────────────────────────────

class Incident(BaseModel):
    """
    The canonical operational entity.
    It aggregates ALL intelligence (Evidence, Risk, AI narratives, Attack Paths)
    into a single reference object for the Dashboard, Alerts, and Reports.
    """
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = Field(..., description="Internal ID of the monitored asset")
    url: str = Field(..., description="The target URL")
    
    # Lifecycle
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_updated_at: datetime = Field(default_factory=datetime.utcnow)
    current_status: IncidentStatus = Field(IncidentStatus.NEW)
    
    # Aggregated Risk Metrics (Copied from Risk Engine for fast indexing)
    security_score: int = Field(...)
    severity: str = Field(...)
    priority: str = Field(...)
    residual_risk: str = Field(..., description="Risk remaining if top mitigations are applied")
    
    # Intelligence References (Foreign Keys to the raw artifacts)
    scan_evidence_ref: str = Field(..., description="Reference to the ScanEvidence document")
    risk_assessment_ref: str = Field(..., description="Reference to the RiskAssessment document")
    explainability_report_ref: Optional[str] = Field(None, description="Reference to the AI ExplainabilityReport document")
    attack_story_ref: Optional[str] = Field(None, description="Reference to the AI Attack Story document")
    
    # Derived Operational Data
    affected_components: List[str] = Field(default_factory=list)
    verified_findings_count: int = Field(0)
    
    monitoring_status: MonitoringStatus = Field(default_factory=MonitoringStatus)
    timeline: IncidentTimeline = Field(default_factory=IncidentTimeline)
    audit_trail: List[AuditEntry] = Field(default_factory=list)


# ── Report Models ─────────────────────────────────────────────────────────────

class ReportMetadata(BaseModel):
    """Tracking info for generated reports."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = Field(...)
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_by: str = Field(..., description="User ID or 'system'")
    format_type: str = Field(..., description="PDF, JSON, HTML")


class ConfidenceMeter(BaseModel):
    """Metrics proving the deterministic nature of the security score."""
    confidence_percentage: int = Field(..., description="e.g., 98")
    verified_sources: List[str] = Field(
        default_factory=list, 
        description="e.g., ['32 Security Checks', 'TLS Analysis', 'Header Analysis', 'Snapshot Comparison', 'Evidence Verified']"
    )


class ExecutiveReport(BaseModel):
    """High-level summary formatted for leadership."""
    metadata: ReportMetadata
    executive_summary: str = Field(...)
    overall_security_score: int = Field(...)
    overall_grade: str = Field(...)
    critical_issues_count: int = Field(0)
    business_impact_summary: str = Field(...)
    attack_path_summary: str = Field(...)
    top_recommendations: List[str] = Field(default_factory=list)
    monitoring_status: str = Field(...)


class TechnicalReport(BaseModel):
    """Exhaustive diagnostic payload formatted for engineering teams."""
    metadata: ReportMetadata
    asset_details: Dict[str, Any] = Field(default_factory=dict)
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    risk_assessment_data: Dict[str, Any] = Field(default_factory=dict)
    owasp_mapping: Dict[str, List[str]] = Field(default_factory=dict)
    security_headers: Dict[str, str] = Field(default_factory=dict)
    tls_information: Dict[str, Any] = Field(default_factory=dict)
    snapshot_changes: Dict[str, Any] = Field(default_factory=dict)
    explainability_data: Dict[str, Any] = Field(default_factory=dict)
    attack_chain_analysis: Dict[str, Any] = Field(default_factory=dict)
    verification_checklists: List[Dict[str, Any]] = Field(default_factory=list)
    residual_risk: str = Field(...)


class DashboardSummary(BaseModel):
    """Lightweight aggregation optimized for the SOC Command Center UI."""
    incident_id: str = Field(...)
    security_score: int = Field(...)
    overall_grade: str = Field(...)
    threat_level: str = Field(..., description="e.g., HIGH, CRITICAL")
    assets_protected: int = Field(...)
    active_incidents: int = Field(...)
    monitoring_active: int = Field(...)
    critical_findings: int = Field(...)
    confidence_meter: ConfidenceMeter = Field(...)
    recent_timeline: IncidentTimeline = Field(...)

"""
risk_engine/models.py — Strongly typed data contracts for the Risk Engine.

This module defines the RiskAssessment Pydantic model using composed 
nested models to ensure clean serialization, easy XAI consumption, and 
strict deterministic evaluation.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional
import uuid

from pydantic import BaseModel, Field


# ── Nested Domain Models ──────────────────────────────────────────────────────

class AssessmentMetadata(BaseModel):
    """Core identifiers and version tracking for the assessment."""
    assessment_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique ID for this assessment")
    evidence_reference: str = Field(..., description="Reference to the source ScanEvidence used")
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="UTC time of generation")
    engine_version: str = Field("1.0", description="Version of the Risk Engine")
    policy_version: str = Field("1.0", description="Version of the scoring policy used")
    assessment_hash: Optional[str] = Field(None, description="SHA-256 hash for integrity verification")


class RiskSummary(BaseModel):
    """High-level scoring and grading."""
    overall_security_score: int = Field(100, description="0-100 overall score (100 = safest)")
    technical_score: int = Field(100, description="0-100 score strictly for technical misconfigurations")
    behavioral_integrity_score: int = Field(100, description="0-100 score for behavioral/defacement aspects")
    overall_grade: str = Field("A+", description="A+, A, B, C, D, F letter grade")
    overall_severity: str = Field("Informational", description="Highest severity among all findings")
    overall_priority: str = Field("Low", description="P1 (Critical) to P5 (Informational)")
    
    # Reserved for Monitoring Manager trends
    previous_score: Optional[int] = Field(None, description="Previous assessment score (populated externally)")
    score_delta: Optional[int] = Field(None, description="Difference from previous score")
    trend: Optional[str] = Field(None, description="Improving, Stable, Declining")


class FindingStatistics(BaseModel):
    """Counts of findings by severity."""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    informational_count: int = 0


class RiskBreakdown(BaseModel):
    """Structural categorization of the risks identified."""
    categories: List[str] = Field(default_factory=list, description="e.g., 'Transport Security', 'HTTP Headers'")
    affected_components: List[str] = Field(default_factory=list, description="e.g., 'Web Server', 'TLS'")


class OwaspSummary(BaseModel):
    """Compliance mapping for OWASP Top 10."""
    global_owasp_categories: List[str] = Field(default_factory=list, description="All distinct OWASP categories observed")


class ConfidenceAssessment(BaseModel):
    """Determinable confidence in the assessment based on evidence completeness."""
    confidence_score: int = Field(100, description="0-100% confidence based on completeness of evidence")
    reason: str = Field("Evidence Complete", description="Deterministic reason for the confidence level")


class AssessmentStatus(BaseModel):
    """Operational status of the assessment generation."""
    status: str = Field("COMPLETED", description="COMPLETED, PARTIAL, FAILED")
    message: Optional[str] = Field(None, description="Error or partial success message if applicable")


class FindingReference(BaseModel):
    """Lightweight reference model for individual findings to prevent data duplication."""
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str = Field(..., description="Title of the deterministic finding")
    severity: str = Field(..., description="Critical, High, Medium, Low, Informational")
    category: str = Field(..., description="Finding category")
    owasp: List[str] = Field(default_factory=list, description="Mapped OWASP Top 10 categories")
    evidence_reference: str = Field(..., description="Link to the specific evidence artifact/field")
    confidence: int = Field(100, description="Confidence in this specific finding")


# ── Root Model ────────────────────────────────────────────────────────────────

class RiskAssessment(BaseModel):
    """
    The complete, deterministic risk evaluation of a website.
    This object never contains AI-generated narrative, recommendations, or business impact.
    """
    metadata: AssessmentMetadata
    summary: RiskSummary
    statistics: FindingStatistics
    breakdown: RiskBreakdown
    owasp: OwaspSummary
    confidence: ConfidenceAssessment
    status: AssessmentStatus
    
    findings: List[FindingReference] = Field(default_factory=list)

    # ── Reserved for XAI (Explainable AI) ─────────────────────────────────────
    xai_reference: Optional[str] = Field(None, description="Reserved for AI Incident Intelligence")
    attack_story_reference: Optional[str] = Field(None, description="Reserved for AI Incident Intelligence")

    class Config:
        extra = "forbid"

"""
evidence_engine/models.py — Strongly typed data contracts for the Evidence Engine.

This module defines the ScanEvidence and EvidenceError Pydantic models. 
It uses small, nested models composed together to represent the single, 
immutable source of truth produced by the Evidence Engine.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EvidenceError(BaseModel):
    """
    Deterministic error model returned when a scan fails.
    Prevents raw exceptions from crashing downstream AI or UI modules.
    """
    success: bool = Field(False, description="Always False for an error")
    error_type: str = Field(..., description="Category of error (e.g., 'TIMEOUT', 'DNS_FAILURE')")
    message: str = Field(..., description="Human-readable error description")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="UTC time of the failure")
    url: str = Field(..., description="The target URL that failed")

    class Config:
        extra = "forbid"


# ── Nested Models ─────────────────────────────────────────────────────────────

class RequestMetadata(BaseModel):
    """Core identifiers and scan metadata."""
    status: str = Field(..., description="Overall scan status: SUCCESS, FAILED, PARTIAL")
    evidence_version: str = Field("1.0", description="Schema version of this evidence object")
    verified: bool = Field(True, description="Indicates evidence was deterministically collected")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="UTC time of the scan")
    url: str = Field(..., description="The original validated URL that was scanned")
    hostname: str = Field(..., description="The parsed hostname of the target")
    resolved_ip: Optional[str] = Field(None, description="The specific IP address connected to (from ssrf_guard)")
    scan_id: Optional[str] = Field(None, description="Unique identifier for this scan operation")
    scan_duration: Optional[float] = Field(None, description="Total duration of the scan pipeline in seconds")
    scan_method: str = Field("HTTP_GET", description="Method used to collect evidence")
    scan_version: str = Field("1.0", description="Version of the Evidence Engine scanner")


class HeaderEvidence(BaseModel):
    """HTTP response and header information."""
    status_code: Optional[int] = Field(None, description="HTTP response status code")
    response_time: Optional[float] = Field(None, description="Time taken for the HTTP response in seconds")
    headers: Dict[str, str] = Field(default_factory=dict, description="Raw HTTP response headers")
    security_headers: Dict[str, str] = Field(default_factory=dict, description="Extracted security-specific headers (e.g., CSP, HSTS)")


class SSLEvidence(BaseModel):
    """TLS handshake and certificate information."""
    tls_information: Dict[str, Any] = Field(default_factory=dict, description="Parsed TLS handshake details (e.g., version, cipher)")
    certificate_information: Dict[str, Any] = Field(default_factory=dict, description="Parsed SSL certificate details (e.g., expiry, issuer)")


class SnapshotMetadata(BaseModel):
    """Integrity information for the HTML snapshot."""
    algorithm: str = Field(default="SHA-256", description="Hashing algorithm used")
    hash: str = Field(..., description="Cryptographic hash of the snapshot")
    snapshot_size: int = Field(..., description="Size of the snapshot in bytes")


class SnapshotEvidence(BaseModel):
    """Snapshot references and reconnaissance files."""
    snapshot_reference: Optional[str] = Field(None, description="URI or path to the stored HTML snapshot")
    snapshot_metadata: Optional[SnapshotMetadata] = Field(None, description="Integrity data for the snapshot")
    robots_txt: Optional[str] = Field(None, description="Contents of robots.txt, if found")
    security_txt: Optional[str] = Field(None, description="Contents of security.txt, if found")


class DiffEvidence(BaseModel):
    """Changes detected from previous scans."""
    html_diff: Optional[str] = Field(None, description="Textual diff between the previous and current snapshot")
    change_type: str = Field("UNKNOWN", description="Classification of change: NONE, CONTENT, STRUCTURE, RESOURCE, SECURITY_HEADERS, UNKNOWN")


class VulnerabilityFinding(BaseModel):
    """A single deterministic finding."""
    category: str = Field(..., description="Category of finding (e.g., 'Technical', 'Behavioral')")
    message: str = Field(..., description="Deterministic description of the finding")


class ScanMetrics(BaseModel):
    """Arbitrary numerical metrics."""
    raw_metrics: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary raw numerical metrics collected during the scan")


# ── Root Model ────────────────────────────────────────────────────────────────

class ScanEvidence(BaseModel):
    """
    Deterministic evidence composed of nested domain models.
    This object never contains AI analysis, severity scores, or subjective recommendations.
    """
    metadata: RequestMetadata
    headers: HeaderEvidence
    ssl: SSLEvidence
    snapshot: SnapshotEvidence
    diff: DiffEvidence
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    metrics: ScanMetrics

    class Config:
        # Prevents arbitrary attributes from being added, enforcing strict adherence to the contract
        extra = "forbid"

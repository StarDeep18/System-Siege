"""
ai/attack_story_models.py — Strongly typed generative data contracts for Attack Path Explorer.

This module defines the Pydantic models for the hypothetical attack graph.
It guarantees that the LLM generates a structured, defensive, and evidence-based 
non-linear graph without producing exploitative payloads or unsupported claims.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional
import uuid

from pydantic import BaseModel, Field


# ── Nested Metadata Models ────────────────────────────────────────────────────

class AttackMetadata(BaseModel):
    """Metadata tracking the generative process and forcing defensive disclaimers."""
    story_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    story_version: str = Field("1.0")
    prompt_version: str = Field("1.0")
    model_name: str = Field("gemini-2.5-flash")
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    confidence: str = Field(..., description="Overall confidence (Low/Medium/High/Very High)")
    disclaimer: str = Field(
        "This is a hypothetical attack scenario generated from verified security findings. No exploitation was performed.",
        description="Mandatory disclaimer that must lead the report."
    )


class EvidenceCoverage(BaseModel):
    """Demonstrates that the AI strictly adhered to the provided evidence."""
    chain_confidence: str = Field(..., description="Confidence (Low/Medium/High/Very High)")
    evidence_coverage_percentage: int = Field(..., description="Percentage of available findings successfully mapped into the attack graph")
    findings_used_count: int = Field(..., description="Total number of findings utilized")
    unused_findings_count: int = Field(..., description="Total number of findings that did not fit into an attack path")


# ── Core Graph Components ─────────────────────────────────────────────────────

class MITREReference(BaseModel):
    """Structured mapping to the MITRE ATT&CK framework."""
    tactic: str = Field(..., description="e.g., Initial Access, Execution, Persistence")
    technique: str = Field(..., description="e.g., Exploit Public-Facing Application")
    confidence: str = Field(..., description="Confidence (Low/Medium/High/Very High)")


class AttackMitigation(BaseModel):
    """Specific defensive action required to 'Break the Chain'."""
    mitigation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id_reference: str = Field(..., description="The finding that must be remediated")
    action_required: str = Field(..., description="e.g., 'Enable CSP Header'")
    why_it_breaks_chain: str = Field(..., description="Explanation of how fixing this halts the attacker's progression")
    residual_risk: str = Field(..., description="The remaining risk level (e.g., 'Medium') after this fix is applied")
    remaining_issues: List[str] = Field(..., description="Other findings that still require attention after this mitigation")


class AttackNode(BaseModel):
    """A distinct state or achievement within the hypothetical attack graph."""
    node_id: str = Field(..., description="Unique ID for this node, used by edges to connect the graph")
    name: str = Field(..., description="e.g., 'Missing CSP', 'Session Theft', 'Website Defacement'")
    description: str = Field(..., description="What the hypothetical attacker achieves at this stage")
    
    # Traceability Metadata
    finding_reference: Optional[str] = Field(None, description="The specific verified finding enabling this node")
    evidence_reference: Optional[str] = Field(None, description="The specific raw evidence artifact cited")
    risk_reference: Optional[str] = Field(None, description="Reference to the assessed severity/priority")
    
    confidence: str = Field(..., description="Confidence (Low/Medium/High/Very High)")
    mitre_mapping: Optional[MITREReference] = Field(None, description="MITRE mapping for this specific node")
    fix_reference: Optional[str] = Field(None, description="ID pointing to an AttackMitigation designed to break this node")


class AttackEdge(BaseModel):
    """A risk transition explaining exactly *why* one node can progress to the next."""
    source_node_id: str = Field(..., description="The ID of the origin AttackNode")
    target_node_id: str = Field(..., description="The ID of the destination AttackNode")
    transition_reason: str = Field(..., description="Explanation of why this transition is possible (e.g., 'Browser allows inline scripts')")
    supporting_evidence: str = Field(..., description="The evidence permitting this transition (e.g., 'Missing CSP Header')")


# ── Attack Chains ─────────────────────────────────────────────────────────────

class AttackChain(BaseModel):
    """A complete, directed graph representing a multi-stage attack path."""
    chain_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    chain_title: str = Field(..., description="e.g., 'Defacement via XSS and Session Theft'")
    entry_node_ids: List[str] = Field(..., description="The IDs of the starting nodes in this graph")
    
    nodes: List[AttackNode] = Field(..., description="All nodes involved in this specific attack path")
    edges: List[AttackEdge] = Field(..., description="The transitions connecting the nodes")
    mitigations: List[AttackMitigation] = Field(..., description="The 'Break the Chain' interventions for this path")


# ── Root Model ────────────────────────────────────────────────────────────────

class AttackStory(BaseModel):
    """
    The complete, defensive, hypothetical attack narrative (Attack Path Explorer).
    Supports multiple non-linear attack chains based strictly on verified evidence.
    """
    metadata: AttackMetadata = Field(default_factory=AttackMetadata)
    coverage: EvidenceCoverage
    
    # ── Narrative Overview ────────────────────────────────────────────────────
    executive_summary: str = Field(..., description="High-level summary of the hypothetical scenarios")
    
    # ── Attack Graphs ─────────────────────────────────────────────────────────
    chains: List[AttackChain] = Field(
        ..., 
        description="Multiple independent attack paths identified from the findings"
    )

    class Config:
        extra = "forbid"

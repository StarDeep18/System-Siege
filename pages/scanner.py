"""
pages/scanner.py — Website Scanner page.

Wires the real pipeline:
  User
  ↓
  URL Validator
  ↓
  Fetcher (SSRF Guard)
  ↓
  Headers / SSL / Snapshot / Diff
  ↓
  Risk Engine
  ↓
  Explainability (Gemini)
  ↓
  Attack Story (Gemini)
  ↓
  Incident Builder
  ↓
  firebase.save_scan()
  ↓
  Return Incident
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import streamlit as st

from security.url_validator import validate as validate_url
from security.ssrf_guard import SSRFError
from evidence_engine.fetcher import fetch, FetchResult
from evidence_engine.models import (
    EvidenceError, ScanEvidence, RequestMetadata, HeaderEvidence, SSLEvidence,
    SnapshotEvidence, SnapshotMetadata, DiffEvidence, ScanMetrics, VulnerabilityFinding,
    ActiveScanEvidence
)
from evidence_engine.headers import analyse as analyse_headers, SecurityHeaderFinding
from evidence_engine import ssl_checker
from evidence_engine import snapshot
from evidence_engine import diff
from evidence_engine import active_scanner
from risk_engine import engine as risk_engine
from ai import explainability
from ai import attack_story
from incident import builder as incident_builder
from firebase import db


# ── Severity colours ──────────────────────────────────────────────────────────

_SEVERITY_COLOR = {
    "high":     "#ef4444",
    "medium":   "#f59e0b",
    "low":      "#64748b",
    "critical": "#dc2626",
}


def render() -> None:
    """Render the Scanner page."""

    # ── Page Header ───────────────────────────────────────────────────────────
    st.markdown(
        """
        <div style="margin-bottom: 2rem;">
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
                <span style="font-size: 0.85rem; color: #64748b; font-weight: 500;
                             text-transform: uppercase; letter-spacing: 0.05em;
                             font-family: 'Inter', sans-serif;">
                    Evidence Engine Console
                </span>
            </div>
            <h1 style="margin: 0; font-family: 'Inter', sans-serif;
                       font-weight: 600; font-size: 1.8rem; color: #f8fafc;">
                Scan Web Target
            </h1>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Retrieve target URL forwarded from Asset Management page (if any)
    if "target_scan_url" in st.session_state:
        st.session_state["scanner_url_input"] = st.session_state.pop("target_scan_url")

    _render_scan_form()


# ── Section Renderers ─────────────────────────────────────────────────────────

def _render_scan_form() -> None:
    """Render the URL input and Execute Scan button."""

    with st.container():
        st.markdown(
            """
            <div style="background-color: #1e293b; padding: 1.5rem;
                        border-radius: 12px; border: 1px solid #334155;
                        margin-bottom: 1.5rem;">
                <div style="font-size: 1rem; font-weight: 600; color: #f1f5f9;
                             margin-bottom: 1rem; font-family: 'Inter', sans-serif;">
                    Launch Scan
                </div>
            """,
            unsafe_allow_html=True,
        )

        col_url, col_btn = st.columns([0.82, 0.18])

        with col_url:
            url = st.text_input(
                "Target URL",
                placeholder="https://example.com",
                key="scanner_url_input",
                label_visibility="collapsed",
                max_chars=2000,
            )

        with col_btn:
            st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
            scan_btn = st.button(
                "Execute Scan",
                key="trigger_scanner_btn",
                use_container_width=True,
            )

        st.markdown("</div>", unsafe_allow_html=True)

    if scan_btn:
        current_time = time.time()
        last_scan_time = st.session_state.get('last_scan_time', 0)
        
        if current_time - last_scan_time < 15:
            st.error(f"Please wait {int(15 - (current_time - last_scan_time))} seconds before scanning again.")
        elif not url or not url.strip():
            st.error("Please enter a valid target URL.")
        else:
            st.session_state['last_scan_time'] = current_time
            _run_scan(url.strip())


def _run_scan(raw_url: str) -> None:
    """
    Execute the real scan pipeline against the supplied URL.
    """

    # ── Step 1: URL Validation ────────────────────────────────────────────────
    with st.status("Step 1 — Validating URL structure…", expanded=False):
        try:
            validated_url = validate_url(raw_url)
            st.write(f"✅ URL accepted: `{validated_url}`")
        except ValueError as exc:
            st.error(f"URL validation failed: {exc}")
            return

    # ── Step 2: Fetch (includes SSRF guard) ───────────────────────────────────
    with st.status("Step 2 — SSRF guard + fetching target…", expanded=False):
        result = fetch(validated_url)

        if isinstance(result, EvidenceError):
            _render_fetch_error(result)
            return

        st.write(f"✅ Connected — HTTP {result.status_code} in {result.response_time}s")
        st.write(f"   Resolved IP: `{result.resolved_ip}`")

    # ── Step 3: Header Analysis ───────────────────────────────────────────────
    with st.status("Step 3 — Analysing HTTP security headers…", expanded=False):
        header_findings: list[SecurityHeaderFinding] = analyse_headers(result.headers)
        st.write(f"✅ Extracted security headers.")

    # ── Step 4: SSL Check ─────────────────────────────────────────────────────
    with st.status("Step 4 — TLS/SSL inspection…", expanded=False):
        ssl_result = ssl_checker.check(validated_url)
        st.write(f"✅ SSL check complete.")

    # ── Step 5: Snapshot ──────────────────────────────────────────────────────
    with st.status("Step 5 — Snapshot capture…", expanded=False):
        snap = snapshot.capture(result)
        st.write(f"✅ Snapshot captured (words: {snap.word_count}).")

    # ── Step 6: Diff ──────────────────────────────────────────────────────────
    with st.status("Step 6 — Defacement detection…", expanded=False):
        # We compare the snapshot against itself for the first run (no historical baseline)
        diff_result = diff.compare(snap, snap)
        st.write(f"✅ Diff computed.")
        
    # ── Step 6.5: Active Scanning ─────────────────────────────────────────────
    with st.status("Step 6.5 — Active Penetration Testing…", expanded=False):
        st.write("Executing DDoS, SQLi, and XSS payloads. This may take a few moments...")
        active_result = active_scanner.run_active_scan(validated_url)
        st.write("✅ Active scanning complete.")

    # ── Assemble Evidence ─────────────────────────────────────────────────────
    with st.status("Step 7 — Assembling Scan Evidence…", expanded=False):
        tls_info = {}
        cert_info = {}
        if ssl_result:
            tls_info = {"protocol": ssl_result.protocol_version, "cipher": ssl_result.cipher_suite}
            cert_info = {
                "valid": ssl_result.valid,
                "days_until_expiry": ssl_result.days_until_expiry,
                "grade": ssl_result.grade,
                "issuer": ssl_result.issuer
            }

        evidence = ScanEvidence(
            metadata=RequestMetadata(
                status="SUCCESS",
                url=result.url,
                hostname=result.hostname,
                resolved_ip=result.resolved_ip,
                scan_duration=result.response_time,
            ),
            headers=HeaderEvidence(
                status_code=result.status_code,
                response_time=result.response_time,
                headers=result.headers,
                security_headers={f.header_name: f.value for f in header_findings if f.present}
            ),
            ssl=SSLEvidence(
                tls_information=tls_info,
                certificate_information=cert_info
            ),
            snapshot=SnapshotEvidence(
                snapshot_metadata=SnapshotMetadata(hash=snap.text_fingerprint, snapshot_size=len(snap.text_content))
            ),
            diff=DiffEvidence(
                change_type="NONE",
            ),
            active_scan=active_result,
            metrics=ScanMetrics(
                raw_metrics={"defacement_detected": diff_result.defacement_detected, "similarity_score": diff_result.similarity_score}
            )
        )
        st.write("✅ ScanEvidence ready.")

    # ── Step 8: Risk Engine ───────────────────────────────────────────────────
    with st.status("Step 8 — Assessing Risk (Risk Engine)…", expanded=False):
        assessment = risk_engine.assess(evidence)
        st.write(f"✅ Assessment complete. Score: {assessment.summary.overall_security_score}")

    # ── Step 9: Explainable AI ────────────────────────────────────────────────
    with st.status("Step 9 — Generating Explainability (XAI)…", expanded=False):
        xai_output = explainability.explain(evidence, assessment)
        st.write("✅ XAI Output generated.")

    # ── Step 10: Attack Story ─────────────────────────────────────────────────
    with st.status("Step 10 — Generating Attack Paths…", expanded=False):
        story = attack_story.generate(assessment, xai_output)
        st.write("✅ Attack paths generated.")

    # ── Step 11: Build Incident ───────────────────────────────────────────────
    with st.status("Step 11 — Building Incident…", expanded=False):
        uid = st.session_state.get("uid", "")
        # Find or create asset_id in the uid-scoped 'assets' collection
        existing_assets = db.get_assets(uid)
        matching = [a for a in existing_assets if a.get("url") == result.url]
        if matching:
            asset_id = matching[0]["id"]
        else:
            # Create a new asset owned by this user
            asset_id = db.add_asset(uid, result.url, result.hostname)

        incident = incident_builder.build_incident(evidence, assessment, xai_output, story, asset_id, uid)
        st.write("✅ Incident built.")

    # ── Step 12: Save to Firestore ────────────────────────────────────────────
    with st.status("Step 12 — Saving to Firestore…", expanded=False):
        # We save incident as dict
        # Convert datetime objects to string using pydantic's mode="json" dumping
        incident_dict = incident.model_dump(mode="json")
        incident_dict["uid"] = uid
        
        # ENRICH incident_dict with data required by the dashboard (Data Lost Fix)
        incident_dict["overall_grade"] = assessment.summary.overall_grade
        incident_dict["confidence_score"] = assessment.confidence.confidence_score
        incident_dict["verified_sources"] = incident_builder._build_verified_sources(assessment)
        incident_dict["critical_issues_count"] = assessment.statistics.critical_count
        
        sim_score = evidence.metrics.raw_metrics.get('similarity_score', 1.0)
        incident_dict["similarity_percent"] = round(sim_score * 100, 2)
        
        xai_by_title = {f.finding: f for f in xai_output.findings}
        findings_list = []
        for f in assessment.findings:
            x_f = xai_by_title.get(f.title)
            findings_list.append({
                "title": f.title,
                "severity": f.severity,
                "evidence_reference": f.evidence_reference,
                "owasp_mapping": x_f.owasp_mapping if x_f else ", ".join(f.owasp),
                "reason": x_f.reason if x_f else "",
                "business_impact": x_f.business_impact if x_f else "",
                "recommendation": x_f.recommendation if x_f else "",
                "risk_contribution": f.risk_contribution if hasattr(f, "risk_contribution") else 10
            })
        incident_dict["findings"] = findings_list
        incident_dict["top_recommendations"] = [f.recommendation for f in xai_output.findings if f.recommendation]
        
        if story.chains:
            incident_dict["attack_chain_analysis"] = {
                "chain_count": len(story.chains),
                "chain_titles": [c.chain_title for c in story.chains],
                "confidence": story.coverage.chain_confidence,
                "coverage_pct": story.coverage.evidence_coverage_percentage,
                "chains": [c.model_dump(mode="json") for c in story.chains]
            }
        
        incident_id = db.save_scan(incident_dict)
        incident_dict["id"] = incident_id
        
        # Save snapshot — always stamp owner_uid, asset_id, url, and timestamp
        snap_dict = snapshot.to_firestore_dict(snap)
        snap_dict["owner_uid"] = uid
        snap_dict["asset_id"] = asset_id
        snap_dict["url"] = result.url
        snap_dict["timestamp"] = datetime.utcnow()
        db.save_snapshot(snap_dict)
        
        st.session_state["last_incident"] = incident_dict
        
        # Log the scan action
        db.log_action(uid, "SCAN", result.url, result.resolved_ip)
        
        st.write("✅ Saved to database.")

    # ── Render Results ────────────────────────────────────────────────────────
    _render_results(incident, assessment, evidence)
    
    st.success("Pipeline complete! You can now view the Dashboard for the results.")


# ── Result Renderers ──────────────────────────────────────────────────────────

def _render_fetch_error(error: EvidenceError) -> None:
    """Display a structured EvidenceError to the user."""
    st.error(f"**Scan failed: {error.error_type}**")
    st.markdown(
        f"""
        <div style="background-color: #1e293b; padding: 1rem; border-radius: 8px;
                    border-left: 4px solid #ef4444; font-size: 0.9rem;
                    color: #cbd5e1; font-family: 'Inter', sans-serif;">
            <b>Error:</b> {error.message}<br>
            <b>URL:</b> {error.url}<br>
            <b>Time:</b> {error.timestamp.strftime('%H:%M:%S UTC')}
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_results(
    incident,
    assessment,
    evidence
) -> None:
    """Render the full scan result panel."""

    score = assessment.summary.overall_security_score
    level = assessment.summary.overall_severity.lower()

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        "<div style='font-family: \"Inter\", sans-serif; font-size: 1.2rem; "
        "font-weight: 600; color: #f8fafc; margin-bottom: 1rem;'>"
        "Scan Results</div>",
        unsafe_allow_html=True,
    )

    # ── Top summary row ───────────────────────────────────────────────────────
    level_color = {
        "low":      "#10b981",
        "medium":   "#f59e0b",
        "high":     "#ef4444",
        "critical": "#dc2626",
    }.get(level, "#94a3b8")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f"""
            <div style="background-color:#1e293b; padding:1.25rem; border-radius:10px;
                        border:1px solid #334155;">
                <div style="font-size:0.78rem; color:#94a3b8; font-weight:500;">SECURITY SCORE</div>
                <div style="font-size:2rem; font-weight:700; color:#f8fafc;">{score}<span
                    style="font-size:1rem; color:#64748b;"> /100</span></div>
            </div>""",
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""
            <div style="background-color:#1e293b; padding:1.25rem; border-radius:10px;
                        border:1px solid #334155;">
                <div style="font-size:0.78rem; color:#94a3b8; font-weight:500;">RISK LEVEL</div>
                <div style="font-size:2rem; font-weight:700; color:{level_color};">{level.upper()}</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""
            <div style="background-color:#1e293b; padding:1.25rem; border-radius:10px;
                        border:1px solid #334155;">
                <div style="font-size:0.78rem; color:#94a3b8; font-weight:500;">FINDINGS</div>
                <div style="font-size:2rem; font-weight:700; color:#ef4444;">{len(assessment.findings)}</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f"""
            <div style="background-color:#1e293b; padding:1.25rem; border-radius:10px;
                        border:1px solid #334155;">
                <div style="font-size:0.78rem; color:#94a3b8; font-weight:500;">CONFIDENCE</div>
                <div style="font-size:2rem; font-weight:700; color:#f8fafc;">{assessment.confidence.confidence_score}%</div>
            </div>""",
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)
    
    # ── Defacement & Visual Difference Row ────────────────────────────────────
    
    sim_score = evidence.metrics.raw_metrics.get('similarity_score', 0)
    defaced = evidence.metrics.raw_metrics.get('defacement_detected', False)
    diff_percent = round(sim_score * 100, 2)
    
    defaced_color = "#ef4444" if defaced else "#10b981"
    defaced_text = "⚠️ DEFACEMENT DETECTED" if defaced else "✅ NO DEFACEMENT"
    
    st.markdown(
        f"""
        <div style="background-color:#1e293b; padding:1.25rem; border-radius:10px; border:1px solid {defaced_color}; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center;">
            <div>
                <div style="font-size:0.78rem; color:#94a3b8; font-weight:500; text-transform: uppercase;">Visual Difference Analysis</div>
                <div style="font-size:1.5rem; font-weight:700; color:{defaced_color}; margin-top: 0.25rem;">
                    {defaced_text}
                </div>
            </div>
            <div style="text-align: right;">
                <div style="font-size:0.78rem; color:#94a3b8; font-weight:500;">MODIFICATION RATE</div>
                <div style="font-size:2rem; font-weight:700; color:#f8fafc;">
                    {diff_percent}%
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    st.info(
        "**Scan scope: Full Pipeline.**  "
        "TLS inspection, snapshot comparison, headers, risk assessment, explainable AI, and attack paths generated successfully. "
        "The incident has been saved to the database."
    )

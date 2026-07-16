"""
pages/reports.py — Incident Reports page.

Displays reports generated from real Incidents produced by the pipeline.
Loads reports from Firebase Firestore (uid-scoped).

NO mock data. NO static JSON. NO hardcoded findings.
Every report rendered here was produced by incident/builder.py
from a real scan of a real URL.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import streamlit as st

from firebase.db import get_reports


# ── Page Entry Point ──────────────────────────────────────────────────────────

def render() -> None:
    """Render the Incident Reports page."""

    st.markdown(
        """
        <div style="margin-bottom: 2rem;">
            <div style="font-size: 0.8rem; color: #64748b; font-weight: 500;
                        text-transform: uppercase; letter-spacing: 0.05em;
                        font-family: 'Inter', sans-serif; margin-bottom: 0.25rem;">
                Executive Documentation
            </div>
            <h1 style="margin: 0; font-family: 'Inter', sans-serif;
                       font-weight: 600; font-size: 1.8rem; color: #f8fafc;">
                Incident Reports
            </h1>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if "selected_report_id" in st.session_state:
        _render_report_detail()
    else:
        _render_report_list()


# ── List View ─────────────────────────────────────────────────────────────────

def _render_report_list() -> None:
    """Load and render all reports for the authenticated user from Firestore."""
    uid = st.session_state.get("uid", "")

    if not uid:
        st.info("Sign in to view your incident reports.")
        return

    try:
        reports = get_reports(uid, limit=50)
    except Exception as exc:
        st.error(f"Could not load reports from Firestore: {exc}")
        return

    if not reports:
        _render_empty_state()
        return

    st.markdown(
        f"<div style='font-size:0.85rem; color:#64748b; margin-bottom:1.5rem;'>"
        f"{len(reports)} incident report(s) on record.</div>",
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)
    for i, report in enumerate(reports):
        with (col1 if i % 2 == 0 else col2):
            _render_report_card(report)


def _render_report_card(report: dict) -> None:
    """Render a single report summary card."""
    score = report.get("overall_security_score", report.get("security_score", report.get("score", "—")))
    grade = report.get("overall_grade", report.get("grade", "—"))
    url = report.get("url", report.get("asset", "Unknown target"))
    generated_at = report.get("generated_at", "")
    report_id = report.get("id", "")
    severity = report.get("severity", report.get("risk_level", "unknown")).upper()

    _color = {
        "CRITICAL": "#dc2626",
        "HIGH":     "#ef4444",
        "MEDIUM":   "#f59e0b",
        "LOW":      "#10b981",
    }.get(severity, "#64748b")

    ts_display = ""
    if isinstance(generated_at, datetime):
        ts_display = generated_at.strftime("%Y-%m-%d %H:%M UTC")
    elif isinstance(generated_at, str):
        ts_display = generated_at[:16]

    st.markdown(
        f"""
        <div style="background-color:#1e293b; padding:1.25rem; border-radius:12px;
                    border:1px solid #334155; margin-bottom:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:0.75rem;">
                <div style="font-size:0.95rem; font-weight:600; color:#f1f5f9;
                             font-family:'Inter',sans-serif; flex:1; margin-right:1rem;">
                    {url}
                </div>
                <div style="font-size:0.75rem; font-weight:600; padding:0.2rem 0.6rem;
                             border-radius:4px; background-color:{_color}22;
                             color:{_color}; border:1px solid {_color}44; white-space:nowrap;">
                    {severity}
                </div>
            </div>
            <div style="display:flex; gap:2rem; font-size:0.82rem; color:#94a3b8; margin-bottom:0.5rem;">
                <span>Score: <b style="color:#f8fafc;">{score}/100</b></span>
                <span>Grade: <b style="color:#f8fafc;">{grade}</b></span>
            </div>
            <div style="font-size:0.78rem; color:#475569;">{ts_display}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("View Report", key=f"view_report_{report_id}", use_container_width=True):
        st.session_state["selected_report_id"] = report_id
        st.session_state["selected_report_data"] = report
        st.rerun()


# ── Detail View ───────────────────────────────────────────────────────────────

def _render_report_detail() -> None:
    """Render the full detail view for a selected report."""
    if st.button("← Back to Reports", key="back_to_reports_btn"):
        st.session_state.pop("selected_report_id", None)
        st.session_state.pop("selected_report_data", None)
        st.rerun()

    report = st.session_state.get("selected_report_data", {})
    if not report:
        st.error("Report data not available. Please go back and try again.")
        return

    url   = report.get("url", report.get("asset", "Unknown"))
    score = report.get("overall_security_score", report.get("security_score", report.get("score", 0)))
    grade = report.get("overall_grade", report.get("grade", "—"))
    severity    = report.get("severity", report.get("risk_level", "unknown")).upper()
    critical    = report.get("critical_issues_count", report.get("critical_count", 0))
    exec_summary = report.get("executive_summary", "")
    biz_impact   = report.get("business_impact_summary", report.get("summary", ""))
    attack_path  = report.get("attack_path_summary", "")
    recommendations = report.get("top_recommendations", [])
    monitoring   = report.get("monitoring_status", "")
    generated_at = report.get("generated_at", "")

    # ── Header ────────────────────────────────────────────────────────────────
    st.markdown(
        f"<h2 style='font-family:\"Inter\",sans-serif; font-weight:600; "
        f"color:#f8fafc; margin-bottom:0.25rem;'>{url}</h2>",
        unsafe_allow_html=True,
    )
    if isinstance(generated_at, datetime):
        ts = generated_at.strftime("%Y-%m-%d %H:%M UTC")
    elif isinstance(generated_at, str):
        ts = generated_at[:16]
    else:
        ts = ""
    st.markdown(
        f"<div style='font-size:0.82rem; color:#64748b; margin-bottom:1.5rem;'>Generated: {ts}</div>",
        unsafe_allow_html=True,
    )

    # ── Metrics row ───────────────────────────────────────────────────────────
    _color = {
        "CRITICAL": "#dc2626", "HIGH": "#ef4444",
        "MEDIUM": "#f59e0b",   "LOW": "#10b981",
    }.get(severity, "#64748b")

    c1, c2, c3, c4 = st.columns(4)
    for col, label, value, color in [
        (c1, "SECURITY SCORE",   f"{score}/100",  "#f8fafc"),
        (c2, "GRADE",            grade,           "#f8fafc"),
        (c3, "SEVERITY",         severity,        _color),
        (c4, "CRITICAL ISSUES",  str(critical),   "#ef4444" if critical > 0 else "#10b981"),
    ]:
        with col:
            st.markdown(
                f"""<div style="background-color:#1e293b; padding:1.25rem; border-radius:10px;
                            border:1px solid #334155; text-align:center;">
                    <div style="font-size:0.72rem; color:#64748b; font-weight:500;
                                 text-transform:uppercase; letter-spacing:0.05em;">{label}</div>
                    <div style="font-size:1.8rem; font-weight:700; color:{color}; margin-top:0.25rem;">{value}</div>
                </div>""",
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Executive Summary ─────────────────────────────────────────────────────
    if exec_summary:
        st.markdown(
            f"""
            <div style="background-color:#1e293b; padding:1.5rem; border-radius:12px;
                        border:1px solid #334155; margin-bottom:1.25rem;">
                <div style="font-size:0.75rem; color:#64748b; font-weight:600;
                             text-transform:uppercase; letter-spacing:0.05em; margin-bottom:0.75rem;">
                    Executive Summary
                </div>
                <p style="font-size:0.95rem; line-height:1.65; color:#cbd5e1;
                           font-family:'Inter',sans-serif; margin:0;">{exec_summary}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Business Impact ───────────────────────────────────────────────────────
    if biz_impact:
        st.markdown(
            f"""
            <div style="background-color:#1e293b; padding:1.5rem; border-radius:12px;
                        border:1px solid #334155; margin-bottom:1.25rem;">
                <div style="font-size:0.75rem; color:#64748b; font-weight:600;
                             text-transform:uppercase; letter-spacing:0.05em; margin-bottom:0.75rem;">
                    Business Impact
                </div>
                <p style="font-size:0.9rem; line-height:1.65; color:#94a3b8;
                           font-family:'Inter',sans-serif; margin:0;">{biz_impact}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Attack Path Summary ───────────────────────────────────────────────────
    if attack_path:
        st.markdown(
            f"""
            <div style="background-color:#1e293b; padding:1.5rem; border-radius:12px;
                        border-left:4px solid #ef4444; border-top:1px solid #334155;
                        border-right:1px solid #334155; border-bottom:1px solid #334155;
                        margin-bottom:1.25rem;">
                <div style="font-size:0.75rem; color:#ef4444; font-weight:600;
                             text-transform:uppercase; letter-spacing:0.05em; margin-bottom:0.75rem;">
                    Attack Path Summary
                </div>
                <p style="font-size:0.9rem; line-height:1.65; color:#94a3b8;
                           font-family:'Inter',sans-serif; margin:0;">{attack_path}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Recommendations ───────────────────────────────────────────────────────
    if recommendations:
        st.markdown(
            "<div style='font-size:0.75rem; color:#64748b; font-weight:600; "
            "text-transform:uppercase; letter-spacing:0.05em; "
            "margin-bottom:0.75rem;'>Top Recommendations</div>",
            unsafe_allow_html=True,
        )
        for i, rec in enumerate(recommendations, 1):
            st.markdown(
                f"""
                <div style="display:flex; align-items:flex-start; gap:0.75rem;
                             margin-bottom:0.6rem; background-color:#1e293b;
                             padding:0.75rem 1rem; border-radius:8px; border:1px solid #334155;">
                    <div style="min-width:20px; height:20px; border-radius:50%;
                                 background-color:#2563eb; color:#fff; font-size:0.7rem;
                                 font-weight:700; display:flex; align-items:center;
                                 justify-content:center;">{i}</div>
                    <div style="font-size:0.88rem; color:#cbd5e1;
                                 font-family:'Inter',sans-serif; line-height:1.4;">{rec}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    if monitoring:
        st.markdown(
            f"<div style='font-size:0.8rem; color:#64748b; margin-top:0.5rem; margin-bottom:1.5rem;'>"
            f"Monitoring: {monitoring}</div>",
            unsafe_allow_html=True,
        )

    # ── Export ────────────────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        "<div style='font-size:1rem; font-weight:600; color:#f1f5f9; "
        "margin-bottom:1rem; font-family:\"Inter\",sans-serif;'>Export Report</div>",
        unsafe_allow_html=True,
    )

    col_pdf, col_json = st.columns(2)

    with col_pdf:
        pdf_bytes = _build_text_pdf(report)
        st.download_button(
            label="Download PDF Report",
            data=pdf_bytes,
            file_name=f"sentinel_report_{report.get('id', 'unknown')}.txt",
            mime="text/plain",
            key="dl_pdf_btn",
            use_container_width=True,
        )

    with col_json:
        # Sanitise the raw Firestore dict for JSON export
        json_safe = {
            k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in report.items()
        }
        json_bytes = json.dumps(json_safe, indent=2, default=str).encode("utf-8")
        st.download_button(
            label="Download JSON Report",
            data=json_bytes,
            file_name=f"sentinel_report_{report.get('id', 'unknown')}.json",
            mime="application/json",
            key="dl_json_btn",
            use_container_width=True,
        )


# ── Empty State ───────────────────────────────────────────────────────────────

def _render_empty_state() -> None:
    st.markdown(
        """
        <div style="display:flex; flex-direction:column; align-items:center;
                    justify-content:center; padding:4rem 2rem; text-align:center;">
            <div style="font-size:3rem; margin-bottom:1rem;">📋</div>
            <h3 style="color:#f1f5f9; font-family:'Inter',sans-serif; margin-bottom:0.5rem;">
                No Reports Yet
            </h3>
            <p style="color:#64748b; font-size:0.9rem; max-width:400px;">
                Run a scan from the Scanner page to generate your first incident report.
                Reports are created automatically after each completed scan.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_text_pdf(report: dict) -> bytes:
    """
    Build a structured plain-text report from the Firestore report dict.
    No external libraries required.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "=" * 72,
        "  SENTINELAI SOC — INCIDENT SECURITY REPORT",
        "=" * 72,
        f"  Report ID:    {report.get('id', '—')}",
        f"  Exported At:  {now}",
        f"  Target URL:   {report.get('url', report.get('asset', '—'))}",
        "=" * 72,
        "",
        "EXECUTIVE SUMMARY",
        "-" * 40,
        report.get("executive_summary", "Not available."),
        "",
        f"Security Score:   {report.get('overall_security_score', report.get('security_score', report.get('score', '—')))} / 100",
        f"Grade:            {report.get('overall_grade', report.get('grade', '—'))}",
        f"Severity:         {report.get('severity', report.get('risk_level', '—'))}",
        f"Critical Issues:  {report.get('critical_issues_count', 0)}",
        f"Monitoring:       {report.get('monitoring_status', '—')}",
        "",
        "BUSINESS IMPACT",
        "-" * 40,
        report.get("business_impact_summary", report.get("summary", "Not available.")),
        "",
        "ATTACK PATH SUMMARY",
        "-" * 40,
        report.get("attack_path_summary", "Not available."),
        "",
        "TOP RECOMMENDATIONS",
        "-" * 40,
    ]

    for i, rec in enumerate(report.get("top_recommendations", []), 1):
        lines.append(f"  {i}. {rec}")

    lines += [
        "",
        "=" * 72,
        "  Generated by SentinelAI SOC.",
        "  All findings are deterministically verified.",
        "=" * 72,
    ]

    return "\n".join(lines).encode("utf-8")

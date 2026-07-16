"""
components/cards.py — Metric cards and glassmorphism content cards.
All cards use custom styles from theme.css via HTML layout injections.
"""

from __future__ import annotations

import html
import streamlit as st
from utils.helpers import score_to_color, score_to_level


# ── Public Interface ──────────────────────────────────────────────────────────

def metric_card(label: str, value: str, delta: str = "", color: str = "#00D4FF", delta_type: str = "neutral") -> None:
    """
    Render a single KPI metric card.
    delta: optional change indicator (e.g. '+3 today' or '-6 pts').
    delta_type: 'up' (increase), 'down' (decrease), or 'neutral'
    """
    delta_class = ""
    if delta_type == "up":
        delta_class = "delta-up"
    elif delta_type == "down":
        delta_class = "delta-down"

    st.markdown(
        f"""
        <div class="glass-panel">
            <div class="metric-container">
                <div class="metric-label">{label}</div>
                <div class="metric-value" style="color: {color};">{value}</div>
                <div class="metric-delta {delta_class}">{delta}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def scan_result_card(scan: dict) -> None:
    """
    Render a summary card for a single scan result.
    Shows URL, risk score badge, defacement status, and timestamp.
    """
    score = scan.get("risk_score", 100)
    badge = risk_badge(score)
    
    defacement_status = "⚠️ DEFACED" if scan.get("defacement_detected") else "✅ Secure"
    defacement_badge_class = "badge-critical" if scan.get("defacement_detected") else "badge-low"
    
    formatted_time = scan.get("timestamp").strftime("%b %d, %H:%M") if hasattr(scan.get("timestamp"), "strftime") else str(scan.get("timestamp"))

    st.markdown(
        f"""
        <div class="glass-panel" style="margin-bottom: 0.75rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                <span style="font-weight: 600; color: #F1F5F9; font-size: 1rem;">{html.escape(scan.get('asset_name', ''))}</span>
                {badge}
            </div>
            <div style="font-size: 0.8rem; color: #94A3B8; word-break: break-all; margin-bottom: 0.5rem;">
                {html.escape(scan.get('url', ''))}
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.5rem; font-size: 0.75rem;">
                <span class="cyber-badge {defacement_badge_class}" style="font-size: 0.65rem; padding: 0.15rem 0.5rem;">
                    {defacement_status}
                </span>
                <span style="color: #475569;">Scanned: {formatted_time}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def asset_card(asset: dict, key_prefix: str = "") -> tuple[bool, bool]:
    """
    Render an asset card with Scan and Delete action buttons.
    Returns (scan_clicked, delete_clicked).
    """
    score = asset.get("risk_score", 100)
    badge = risk_badge(score)
    
    defacement_status = "⚠️ DEFACED" if asset.get("defacement_detected") else "✅ Secure"
    defacement_badge_class = "badge-critical" if asset.get("defacement_detected") else "badge-low"
    
    formatted_time = asset.get("last_scanned").strftime("%b %d, %H:%M") if hasattr(asset.get("last_scanned"), "strftime") else str(asset.get("last_scanned"))

    st.markdown(
        f"""
        <div class="glass-panel" style="margin-bottom: 1rem; padding: 1.25rem !important;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
                <span style="font-weight: 600; color: #F1F5F9; font-size: 1.05rem;">{html.escape(asset.get('name', ''))}</span>
                {badge}
            </div>
            <div style="font-size: 0.8rem; color: #94A3B8; margin-bottom: 0.75rem; word-break: break-all;">
                {html.escape(asset.get('url', ''))}
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                <span class="cyber-badge {defacement_badge_class}" style="font-size: 0.65rem; padding: 0.15rem 0.5rem;">
                    {defacement_status}
                </span>
                <span style="font-size: 0.75rem; color: #475569;">Vulns: <b>{asset.get('vulns')}</b></span>
            </div>
            <div style="font-size: 0.7rem; color: #94A3B8; margin-bottom: 0.75rem;">
                Last Scan: {formatted_time}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    # Custom button layout for Scan and Delete
    col1, col2 = st.columns(2)
    scan_clicked = col1.button("🔍 Scan Now", key=f"scan_asset_{asset.get('id')}_{key_prefix}")
    delete_clicked = col2.button("🗑️ Remove", key=f"delete_asset_{asset.get('id')}_{key_prefix}")
    
    return scan_clicked, delete_clicked


def report_card(report: dict, key_prefix: str = "") -> bool:
    """
    Render a report summary card with a View button.
    Returns True if view button is clicked.
    """
    score = report.get("risk_score", 100)
    badge = risk_badge(score)
    formatted_time = report.get("generated_at").strftime("%b %d, %H:%M") if hasattr(report.get("generated_at"), "strftime") else str(report.get("generated_at"))

    st.markdown(
        f"""
        <div class="glass-panel" style="margin-bottom: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                <span style="font-weight: 600; color: #F1F5F9; font-size: 1.05rem;">{html.escape(report.get('title', ''))}</span>
                {badge}
            </div>
            <div style="font-size: 0.85rem; color: #94A3B8; margin-bottom: 0.75rem;">
                Asset: <b>{html.escape(report.get('asset', ''))}</b>
            </div>
            <p style="font-size: 0.8rem; color: #64748B; margin-bottom: 1rem; line-height: 1.4;">
                {html.escape(report.get('summary', ''))}
            </p>
            <div style="font-size: 0.7rem; color: #475569; margin-bottom: 0.5rem;">
                Generated: {formatted_time}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    return st.button("📄 View Executive Report", key=f"view_report_{report.get('id')}_{key_prefix}")


def risk_badge(score: int) -> str:
    """Return an HTML risk badge string coloured by score."""
    color = score_to_color(score)
    level = score_to_level(score)
    
    badge_class = "badge-low"
    if level == "critical":
        badge_class = "badge-critical"
    elif level == "high":
        badge_class = "badge-high"
    elif level == "medium":
        badge_class = "badge-medium"
        
    return f'<span class="cyber-badge {badge_class}">SCORE {score} ({level})</span>'


def glass_container(title: str = "") -> None:
    """
    Open a custom styled div tag for a glass container.
    Use with st.markdown inside a wrapper or display raw HTML.
    """
    header_html = f"<div style='font-size: 1rem; font-family: \"Space Grotesk\", sans-serif; font-weight:600; color:#F1F5F9; border-bottom: 1px solid rgba(0, 212, 255, 0.15); padding-bottom: 0.5rem; margin-bottom:1rem;'>{title}</div>" if title else ""
    st.markdown(
        f"""
        <div class="glass-panel">
            {header_html}
        """,
        unsafe_allow_html=True
    )

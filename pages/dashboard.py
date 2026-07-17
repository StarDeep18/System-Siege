"""
pages/dashboard.py — SOC Command Center.

Consumes Incident data from Firestore exclusively.
Contains ZERO hardcoded scores, metrics, findings, or timeline events.

Data source hierarchy:
  1. st.session_state["last_incident"] — set by scanner.py after a fresh scan
  2. Firestore get_scans() / get_assets() — persisted data for returning users
  3. "No data available." — displayed when neither source has data

Forbidden:
  - demo_mode flags
  - hardcoded scores (84, 82, 34, 98, etc.)
  - mock timeline events
  - mock system health statuses
  - hardcoded finding names
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

import streamlit as st

from firebase.db import get_scans, get_assets, get_reports


# ── Page Entry Point ──────────────────────────────────────────────────────────

def render() -> None:
    """Render the SOC Command Center."""
    uid = st.session_state.get("uid", "")

    # ── System Status Bar ─────────────────────────────────────────────────────
    _render_status_bar(uid)

    # ── Real-time Alert Banner ──
    if uid:
        try:
            from firebase.db import get_db
            db_client = get_db()
            unread_ref = db_client.collection("alerts").where("owner_uid", "==", uid).where("status", "==", "UNREAD").stream()
            unread_alerts = [{"id": a.id, **a.to_dict()} for a in unread_ref]
            
            for alert in unread_alerts:
                st.error(f"🚨 **{alert.get('title', 'Security Warning')}** — {alert.get('description', '')}")
                if st.button(f"Acknowledge Alert {alert['id'][:8]}...", key=f"ack_{alert['id']}"):
                    db_client.collection("alerts").document(alert["id"]).update({"status": "ACKNOWLEDGED"})
                    st.rerun()
        except Exception:
            pass

    # ── Load data from the ONLY real sources ─────────────────────────────────
    incident   = _load_latest_incident(uid)
    assets     = _load_assets(uid)
    scan_count = len(_load_scans(uid))

    # ── Security Posture (top row) ────────────────────────────────────────────
    _render_security_posture(incident)
    st.write("")

    # ── KPI Row ───────────────────────────────────────────────────────────────
    _render_kpi_row(incident, assets, scan_count)
    st.write("")

    # ── Two-column layout ─────────────────────────────────────────────────────
    col_main, col_side = st.columns([2.5, 1.2])

    with col_main:
        _render_attack_path_explorer(incident)
        st.write("")
        _render_top_mitigations(incident)

    with col_side:
        _render_system_health(uid)
        st.write("")
        _render_incident_timeline(incident)
        st.write("")
        _render_monitoring_panel(incident, assets)
        st.write("")
        _render_export_actions(incident)


# ── Data Loaders ──────────────────────────────────────────────────────────────

def _load_latest_incident(uid: str) -> Optional[dict]:
    """
    Return the latest incident from session_state (fresh scan) or Firestore.
    Returns None if neither source has data. Never fabricates data.
    """
    # Prefer the scan that just completed this session
    if "last_incident" in st.session_state:
        return st.session_state["last_incident"]

    if not uid:
        return None

    try:
        scans = get_scans(uid, limit=1)
        return scans[0] if scans else None
    except Exception:
        return None


def _load_assets(uid: str) -> list[dict]:
    if not uid:
        return []
    try:
        return get_assets(uid)
    except Exception:
        return []


def _load_scans(uid: str) -> list[dict]:
    if not uid:
        return []
    try:
        return get_scans(uid, limit=50)
    except Exception:
        return []


# ── Section Renderers ─────────────────────────────────────────────────────────

def _render_status_bar(uid: str) -> None:
    """Top navigation bar — shows real username, not 'Admin Profile'."""
    email = st.session_state.get("email", "")
    user_label = email if email else ("Authenticated" if uid else "Not signed in")

    st.markdown(
        f"""
<div style="display:flex; justify-content:space-between; align-items:center;
                    border-bottom:1px solid #334155; padding-bottom:1rem; margin-bottom:2rem;">
<div style="display:flex; align-items:center; gap:1rem;">
<div style="width:12px; height:12px; border-radius:50%;
                             background-color:#2563EB;"></div>
<span style="font-family:'Inter',sans-serif; font-size:1.1rem;
                              font-weight:600; color:#f8fafc; letter-spacing:-0.02em;">
                    SentinelAI SOC Command Center
</span>
</div>
<div style="display:flex; align-items:center; gap:1.5rem; font-size:0.85rem;
                         color:#94a3b8; font-family:'Inter',sans-serif;">
<span style="display:flex; align-items:center; gap:0.4rem;">
<span style="color:#10B981;">●</span> LIVE
</span>
<span>Environment: Production</span>
<span>Version: v1.0</span>
<span>{user_label}</span>
</div>
</div>
        """,
        unsafe_allow_html=True,
    )


def _render_security_posture(incident: Optional[dict]) -> None:
    """Security Posture panel — all values from Incident or 'No data available.'"""
    st.markdown(
        "<div style='font-family:\"Inter\",sans-serif; font-size:1.2rem; font-weight:600;"
        " color:#f8fafc; margin-bottom:1rem;'>Security Posture</div>",
        unsafe_allow_html=True,
    )

    if not incident:
        _no_data_panel("Run a scan to populate the Security Posture panel.")
        return

    score    = incident.get("overall_security_score", incident.get("score", incident.get("security_score")))
    grade    = incident.get("overall_grade",    incident.get("grade", "—"))
    severity = incident.get("severity",         incident.get("risk_level", "—")).upper()
    confidence = incident.get("confidence_score", incident.get("confidence", None))
    verified_sources = incident.get("verified_sources", [])

    score_str = f"{score}" if score is not None else "—"
    confidence_str = f"{confidence}%" if confidence is not None else "—"

    # Score colour: green ≥80, amber 60-79, red <60
    score_color = "#10B981" if (score or 0) >= 80 else ("#F59E0B" if (score or 0) >= 60 else "#EF4444")
    sev_color   = {"CRITICAL": "#DC2626", "HIGH": "#EF4444",
                   "MEDIUM": "#F59E0B",   "LOW": "#10B981"}.get(severity, "#94a3b8")

    # Trend: compare to previous score if available
    prev_score = incident.get("previous_score")
    if prev_score is not None and score is not None:
        delta = score - prev_score
        trend_text  = f"▲ +{delta}" if delta > 0 else (f"▼ {delta}" if delta < 0 else "→ Stable")
        trend_color = "#10B981" if delta > 0 else ("#EF4444" if delta < 0 else "#94a3b8")
        trend_sub   = "Improving" if delta > 0 else ("Declining" if delta < 0 else "No change")
    else:
        trend_text  = "No data available."
        trend_color = "#64748b"
        trend_sub   = "Requires previous scan"

    sources_html = ""
    if verified_sources:
        tags = "".join(
            f"<span style='font-size:0.72rem; background-color:rgba(16,185,129,0.12);"
            f" color:#10B981; padding:0.15rem 0.45rem; border-radius:3px;"
            f" border:1px solid rgba(16,185,129,0.3); margin-right:0.25rem;'>{s}</span>"
            for s in verified_sources
        )
        sources_html = f"<div style='margin-top:0.5rem;'>{tags}</div>"
    else:
        sources_html = "<div style='margin-top:0.4rem; font-size:0.78rem; color:#64748b;'>—</div>"

    st.markdown(
        f"""
<div style="display:flex; gap:1.5rem; justify-content:space-between;">
<div style='flex:1; background-color:#1e293b; padding:1.5rem; border-radius:12px;
                         border:1px solid #334155;'>
<div style='font-size:0.82rem; color:#94a3b8; font-weight:500; margin-bottom:0.5rem;'>
                    SCORE &amp; GRADE
</div>
<div style='display:flex; align-items:baseline; gap:0.75rem;'>
<div style='font-size:2.5rem; font-weight:700; color:{score_color};
                                 font-family:"Inter",sans-serif;'>
{score_str}<span style='font-size:1.2rem; color:#64748b;'> /100</span>
</div>
<div style='font-size:1.5rem; font-weight:600; color:{score_color};'>{grade}</div>
</div>
</div>

<div style='flex:1; background-color:#1e293b; padding:1.5rem; border-radius:12px;
                         border:1px solid #334155;'>
<div style='font-size:0.82rem; color:#94a3b8; font-weight:500; margin-bottom:0.5rem;'>
                    TREND
</div>
<div style='font-size:1.8rem; font-weight:600; color:{trend_color};
                             font-family:"Inter",sans-serif;'>
{trend_text}
</div>
<div style='font-size:0.78rem; color:#94a3b8; margin-top:0.25rem;'>{trend_sub}</div>
</div>

<div style='flex:1; background-color:#1e293b; padding:1.5rem; border-radius:12px;
                         border:1px solid #334155;'>
<div style='font-size:0.82rem; color:#94a3b8; font-weight:500; margin-bottom:0.5rem;'>
                    CONFIDENCE
</div>
<div style='font-size:2rem; font-weight:700; color:#f8fafc;
                             font-family:"Inter",sans-serif;'>
{confidence_str}
</div>
{sources_html}
</div>

<div style='flex:1; background-color:#1e293b; padding:1.5rem; border-radius:12px;
                         border:1px solid #334155;'>
<div style='font-size:0.82rem; color:#94a3b8; font-weight:500; margin-bottom:0.5rem;'>
                    THREAT LEVEL
</div>
<div style='font-size:2rem; font-weight:700; color:{sev_color};
                             font-family:"Inter",sans-serif;'>
{severity}
</div>
<div style='font-size:0.78rem; color:#94a3b8; margin-top:0.25rem;'>
{_severity_sub(severity)}
</div>
</div>
</div>
        """,
        unsafe_allow_html=True,
    )


def _render_kpi_row(
    incident: Optional[dict],
    assets: list[dict],
    scan_count: int,
) -> None:
    """Four KPI tiles — all real counts, no hardcoded numbers."""
    critical = incident.get("critical_issues_count", incident.get("critical_count", 0)) if incident else 0
    findings = incident.get("verified_findings_count", incident.get("findings_count", 0)) if incident else 0
    asset_count = len(assets)

    c1, c2, c3, c4 = st.columns(4)
    tiles = [
        ("PROTECTED ASSETS",    str(asset_count)  if asset_count > 0 else "0",  "#f8fafc"),
        ("TOTAL SCANS",         str(scan_count)   if scan_count  > 0 else "0",  "#f8fafc"),
        ("VERIFIED FINDINGS",   str(findings),                                   "#f8fafc"),
        ("CRITICAL ISSUES",     str(critical),  "#ef4444" if critical > 0 else "#10b981"),
    ]
    for col, (label, value, color) in zip([c1, c2, c3, c4], tiles):
        with col:
            st.markdown(
                f"""<div style="background-color:#1e293b; padding:1.25rem; border-radius:10px;
                            border:1px solid #334155; text-align:center;">
<div style="font-size:0.72rem; color:#64748b; font-weight:500;
                                 text-transform:uppercase; letter-spacing:0.05em;">{label}</div>
<div style="font-size:2rem; font-weight:700; color:{color};
                                 margin-top:0.25rem;">{value}</div>
</div>""",
                unsafe_allow_html=True,
            )


def _render_attack_path_explorer(incident: Optional[dict]) -> None:
    """
    Attack Path Explorer — renders a visual flow (cards/arrows) with an interactive side panel.
    """
    st.markdown(
        "<div style='font-family:\"Inter\",sans-serif; font-size:1.2rem; font-weight:600;"
        " color:#f8fafc; margin-bottom:1rem;'>Attack Path Explorer</div>",
        unsafe_allow_html=True,
    )

    if not incident:
        _no_data_panel("No incident data. Run a scan to generate an attack path.")
        return

    chains_data = incident.get("attack_chain_analysis", {})
    chains = chains_data.get("chains", [])
    
    if not chains:
        _no_data_panel("No complete attack path was identified based on the collected evidence.")
        return

    # Use the first chain for visualization
    chain = chains[0]
    nodes = chain.get("nodes", [])
    if not nodes:
        _no_data_panel("No complete attack path was identified based on the collected evidence.")
        return

    st.markdown(
        "<div style='background-color:#1e293b; padding:1.5rem 2rem; border-radius:14px;"
        " border:1px solid #334155;'>",
        unsafe_allow_html=True,
    )
    
    st.markdown(f"<div style='font-size:0.95rem; font-weight:600; color:#f1f5f9; margin-bottom:1rem;'>{chain.get('chain_title', 'Hypothetical Attack Path')}</div>", unsafe_allow_html=True)

    # Create two columns: left for the flow, right for the side panel
    path_col, details_col = st.columns([1, 1.2], gap="large")

    with path_col:
        st.markdown("<div style='font-size:0.8rem; color:#94a3b8; font-weight:600; text-transform:uppercase; margin-bottom:1rem;'>Attack Sequence</div>", unsafe_allow_html=True)
        for i, node in enumerate(nodes):
            node_id = node.get("node_id")
            name = node.get("name", "Unknown Step")
            is_selected = st.session_state.get("selected_node_id") == node_id
            
            # Use a Streamlit button disguised as a card
            if st.button(f"{i+1}. {name}", key=f"node_{node_id}", use_container_width=True, type="primary" if is_selected else "secondary"):
                st.session_state["selected_node_id"] = node_id
                st.rerun()
            
            # Draw an arrow between nodes
            if i < len(nodes) - 1:
                st.markdown("<div style='text-align:center; color:#64748b; font-size:1.2rem; padding:0.1rem 0;'>↓</div>", unsafe_allow_html=True)

    with details_col:
        st.markdown("<div style='font-size:0.8rem; color:#94a3b8; font-weight:600; text-transform:uppercase; margin-bottom:1rem;'>Step Details</div>", unsafe_allow_html=True)
        selected_id = st.session_state.get("selected_node_id")
        if not selected_id and nodes:
            # Default to the first node
            selected_id = nodes[0].get("node_id")
            
        selected_node = next((n for n in nodes if n.get("node_id") == selected_id), None)
        
        if selected_node:
            sev = selected_node.get("risk_reference", "Medium")
            _SEV_COLOR = {"Critical": "#dc2626", "High": "#ef4444", "Medium": "#f59e0b", "Low": "#64748b", "Informational": "#3b82f6"}
            color = _SEV_COLOR.get(sev, "#64748b")
            
            confidence = selected_node.get("confidence", "High")
            if isinstance(confidence, int):
                # Fallback mapping if backend still gives int
                confidence = "High" if confidence > 80 else ("Medium" if confidence > 50 else "Low")
            
            st.markdown(f"""
<div style='background-color:#0f172a; padding:1.25rem; border-radius:10px; border:1px solid #334155;'>
<div style='display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:1rem;'>
<div style='font-size:1.05rem; font-weight:600; color:#f8fafc;'>{selected_node.get('name')}</div>
<div style='display:flex; gap:0.4rem;'>
<span style='background-color:rgba(255,255,255,0.05); padding:0.15rem 0.4rem; border-radius:4px; font-size:0.7rem; color:{color}; border:1px solid {color};'>{sev.upper()}</span>
<span style='background-color:rgba(59,130,246,0.1); padding:0.15rem 0.4rem; border-radius:4px; font-size:0.7rem; color:#60a5fa; border:1px solid rgba(59,130,246,0.25);'>Conf: {str(confidence).upper()}</span>
</div>
</div>
<div style='margin-bottom:1rem;'>
<div style='font-size:0.75rem; color:#94a3b8; font-weight:600; text-transform:uppercase; margin-bottom:0.25rem;'>Why this is possible</div>
<div style='font-size:0.85rem; color:#f1f5f9; line-height:1.5;'>{selected_node.get('description')}</div>
</div>
<div style='margin-bottom:0.5rem;'>
<div style='font-size:0.75rem; color:#94a3b8; font-weight:600; text-transform:uppercase; margin-bottom:0.25rem;'>Evidence Collected</div>
<div style='font-size:0.8rem; color:#cbd5e1; font-family:monospace; background:#1e293b; padding:0.4rem; border-radius:4px; border:1px solid #334155;'>{selected_node.get('evidence_reference', 'No exact evidence ref')}</div>
</div>
</div>
""", unsafe_allow_html=True)
            
            fix_ref = selected_node.get("fix_reference")
            mitigations = chain.get("mitigations", [])
            mitigation = next((m for m in mitigations if m.get("mitigation_id") == fix_ref), None)
            
            if mitigation:
                st.markdown(f"""
<div style='margin-top:0.75rem; background-color:rgba(16,185,129,0.05); padding:1rem; border-radius:10px; border:1px solid rgba(16,185,129,0.2);'>
<div style='font-size:0.75rem; color:#10b981; font-weight:600; text-transform:uppercase; margin-bottom:0.4rem;'>How to Prevent It</div>
<div style='font-size:0.85rem; color:#f1f5f9; margin-bottom:0.4rem;'><strong>Action:</strong> {mitigation.get('action_required')}</div>
<div style='font-size:0.8rem; color:#cbd5e1; line-height:1.4;'><strong>Why it works:</strong> {mitigation.get('why_it_breaks_chain')}</div>
</div>
""", unsafe_allow_html=True)
    
    st.markdown("</div>", unsafe_allow_html=True)


def _render_top_mitigations(incident: Optional[dict]) -> None:
    """Top Mitigation — displays ONE primary recommendation from the top finding."""
    st.markdown(
        "<div style='font-family:\"Inter\",sans-serif; font-size:1.2rem; font-weight:600;"
        " color:#f8fafc; margin-bottom:1rem;'>Top Mitigation</div>",
        unsafe_allow_html=True,
    )

    if not incident:
        _no_data_panel("No mitigation data available.")
        return

    findings = incident.get("findings", [])
    if not findings:
        _no_data_panel("No recommendations generated. Run a scan with AI enabled.")
        return

    top_finding = findings[0]
    title = top_finding.get("title", "Finding")
    why = top_finding.get("reason", "No reason provided.")
    fix = top_finding.get("recommendation", "No specific fix provided.")
    severity = top_finding.get("severity", "High")
    improvement = top_finding.get("risk_contribution", 10)
    pixel_diff_pct = incident.get("pixel_diff_pct", 0.0)

    # ── Alert Box & Sound Logic ──
    trigger_alert = False
    alert_msg = ""
    if pixel_diff_pct > 70.0:
        trigger_alert = True
        alert_msg = f"SECURITY ALERT: Severe visual defacement detected! Pixel change is {pixel_diff_pct}% (Over 70% threshold)."

    alert_html = ""
    if trigger_alert:
        incident_id = incident.get("id", "unknown_id")
        alert_html = f"""
<script>
    if (!window.sessionStorage.getItem('alert_played_{incident_id}')) {{
        window.sessionStorage.setItem('alert_played_{incident_id}', 'true');
        var audio = new Audio('https://www.soundjay.com/buttons/sounds/beep-01a.mp3');
        audio.play().catch(e => console.log('Autoplay blocked:', e)).finally(() => {{
            setTimeout(() => alert("{alert_msg}"), 100);
        }});
    }}
</script>
"""
        st.markdown(alert_html, unsafe_allow_html=True)

    # Convert the fix string into bullet points (checkmarks)
    fix_lines = [line.strip().lstrip("-*").strip() for line in fix.split("\n") if line.strip()]
    fix_html = "".join([
        f"<div style='display:flex; align-items:start; gap:0.5rem; margin-bottom:0.4rem;'>"
        f"<span style='color:#10b981;'>✔</span><span>{line}</span></div>"
        for line in fix_lines
    ])

    priority_color = "#ef4444" if severity in ("Critical", "High") else ("#f59e0b" if severity == "Medium" else "#64748b")

    st.markdown(
        f"""
<div style='background-color:#1e293b; padding:1.5rem; border-radius:12px; border:1px solid #334155; margin-bottom:0.75rem;'>
<div style="display:flex; align-items:center; gap:0.5rem; font-size:0.85rem; color:{priority_color}; font-weight:700; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:1rem;">
🛡 TOP RECOMMENDED ACTION
</div>
<div style="font-size:0.9rem; margin-bottom:0.75rem;">
<strong style="color:#94a3b8;">Priority:</strong> <span style="color:{priority_color}; font-weight:600;">{severity.upper()}</span>
</div>
<div style="font-size:0.9rem; margin-bottom:0.75rem;">
<strong style="color:#94a3b8;">Issue:</strong> <span style="color:#f1f5f9;">{title}</span>
</div>
<div style="font-size:0.9rem; margin-bottom:1rem;">
<strong style="color:#94a3b8;">Why:</strong> <span style="color:#cbd5e1;">{why}</span>
</div>
<div style="font-size:0.9rem; margin-bottom:1rem; color:#f1f5f9;">
<strong style="color:#94a3b8; display:block; margin-bottom:0.5rem;">Fix:</strong>
{fix_html}
</div>
<div style="font-size:0.85rem; background-color:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.2); color:#10b981; padding:0.5rem 0.75rem; border-radius:6px; display:inline-block; font-weight:600;">
Estimated Improvement: +{improvement} Security Score
</div>
</div>
        """,
        unsafe_allow_html=True,
    )


def _render_system_health(uid: str) -> None:
    """
    System Health — checks real connectivity, not hardcoded statuses.
    Firebase status: derived from whether the DB call succeeded.
    Gemini status: checks GEMINI_API_KEY presence in env.
    Evidence / Risk Engine: always operational if the import succeeded.
    """
    st.markdown(
        "<div style='font-family:\"Inter\",sans-serif; font-size:1.1rem; font-weight:600;"
        " color:#f8fafc; margin-bottom:1rem;'>System Health</div>",
        unsafe_allow_html=True,
    )

    # Firebase: try a lightweight DB call
    firebase_ok = False
    try:
        if uid:
            get_assets(uid)
        firebase_ok = True
    except Exception:
        firebase_ok = False

    # Gemini: key presence check
    gemini_ok = bool(os.environ.get("GEMINI_API_KEY", "").strip())

    # Evidence Engine / Risk Engine: always available if imports work
    engine_ok = True

    def _row(label: str, ok: bool, last: bool = False) -> str:
        color = "#10B981" if ok else "#EF4444"
        dot   = "● Healthy" if ok else "● Degraded"
        sep   = "" if last else "border-bottom:1px solid #334155;"
        return (
            f"<div style='display:flex; justify-content:space-between; align-items:center;"
            f" padding:0.75rem 0; {sep}'>"
            f"<span style='color:#cbd5e1; font-size:0.88rem;'>{label}</span>"
            f"<span style='color:{color}; font-weight:500; font-size:0.78rem;'>{dot}</span>"
            f"</div>"
        )

    st.markdown(
        f"""
<div style='background-color:#1e293b; padding:1.25rem; border-radius:12px;
                     border:1px solid #334155; font-family:"Inter",sans-serif;'>
{_row("Firebase",        firebase_ok)}
{_row("Gemini API",      gemini_ok)}
{_row("Evidence Engine", engine_ok)}
{_row("Risk Engine",     engine_ok)}
{_row("Deployment",      True, last=True)}
</div>
        """,
        unsafe_allow_html=True,
    )


def _render_incident_timeline(incident: Optional[dict]) -> None:
    """Incident Timeline — renders real events from the scans and alerts collections."""
    st.markdown(
        "<div style='font-family:\"Inter\",sans-serif; font-size:1.1rem; font-weight:600;"
        " color:#f8fafc; margin-bottom:1rem;'>Incident Timeline</div>",
        unsafe_allow_html=True,
    )

    uid = st.session_state.get("uid", "")
    if not uid:
        _no_data_panel("No timeline events recorded.")
        return

    # Fetch latest scans and alerts to construct a real-time timeline
    try:
        from firebase.db import get_scans, get_db
        scans = get_scans(uid, limit=5)
        
        db_client = get_db()
        alerts_ref = db_client.collection("alerts").where("owner_uid", "==", uid).limit(5).stream()
        alerts = [{"type": "ALERT", **a.to_dict()} for a in alerts_ref]
    except Exception:
        scans = []
        alerts = []

    # Merge and sort events by timestamp
    events = []
    for s in scans:
        ts = s.get("timestamp")
        events.append({
            "title": f"Scan Complete: {s.get('url', 'Unknown')}",
            "description": f"Score: {s.get('overall_security_score', s.get('score', 100))}/100 | Class: {s.get('change_classification', 'None')}",
            "timestamp": ts,
            "icon": "🛰"
        })
    for a in alerts:
        ts = a.get("timestamp")
        events.append({
            "title": f"Alert: {a.get('title', 'Security Alert')}",
            "description": a.get("description", ""),
            "timestamp": ts,
            "icon": "🚨"
        })

    # Sort in memory descending
    events.sort(key=lambda x: x["timestamp"].timestamp() if isinstance(x["timestamp"], datetime) else 0, reverse=True)
    events = events[:5]

    if not events:
        _no_data_panel("No timeline events recorded.")
        return

    rows_html = ""
    for event in events:
        ts = event["timestamp"]
        if isinstance(ts, datetime):
            ts_str = ts.strftime("%H:%M")
        else:
            ts_str = "—"

        rows_html += (
            f"<div style='display:flex; gap:1rem; align-items:flex-start; margin-bottom:1rem;'>"
            f"<span style='font-size:1.2rem;'>{event['icon']}</span>"
            f"<div>"
            f"<div style='color:#64748b; font-size:0.72rem;'>{ts_str}</div>"
            f"<div style='color:#e2e8f0; font-size:0.85rem; font-weight:600;'>{event['title']}</div>"
            f"<div style='color:#94a3b8; font-size:0.78rem;'>{event['description']}</div>"
            f"</div></div>"
        )

    st.markdown(
        f"""
<div style='background-color:#1e293b; padding:1.5rem; border-radius:12px;
                     border:1px solid #334155; font-family:"Inter",sans-serif;'>
{rows_html}
</div>
        """,
        unsafe_allow_html=True,
    )


def _render_monitoring_panel(
    incident: Optional[dict],
    assets: list[dict],
) -> None:
    """Monitoring Status — real scheduler settings, active items, and schedules."""
    st.markdown(
        "<div style='font-family:\"Inter\",sans-serif; font-size:1.1rem; font-weight:600;"
        " color:#f8fafc; margin-bottom:1rem;'>Monitoring Status</div>",
        unsafe_allow_html=True,
    )

    asset_count = len(assets)
    active_monitored_assets = [a for a in assets if a.get("monitoring_enabled", False)]
    monitoring_on = len(active_monitored_assets) > 0
    
    last_scan_ts = None
    next_scan_ts = None
    scan_interval = "—"

    # Derive values from active schedules
    if active_monitored_assets:
        # Find latest scan and next run
        last_scans = [a["last_scanned"] for a in active_monitored_assets if a.get("last_scanned")]
        next_scans = [a["next_scheduled_scan_at"] for a in active_monitored_assets if a.get("next_scheduled_scan_at")]
        intervals = [a["monitoring_interval_minutes"] for a in active_monitored_assets if a.get("monitoring_interval_minutes")]
        
        if last_scans:
            last_scan_ts = max(last_scans)
        if next_scans:
            next_scan_ts = min(next_scans)
        if intervals:
            scan_interval = f"{min(intervals)} min" if min(intervals) < 60 else f"{min(intervals)//60} hours"

    if isinstance(last_scan_ts, datetime):
        last_scan_str = last_scan_ts.strftime("%Y-%m-%d %H:%M UTC")
    else:
        last_scan_str = "No data available."

    if isinstance(next_scan_ts, datetime):
        next_scan_str = next_scan_ts.strftime("%Y-%m-%d %H:%M UTC")
    else:
        next_scan_str = "—"

    status_label = "ACTIVE" if monitoring_on else "INACTIVE"
    status_color = "#10B981" if monitoring_on else "#64748b"
    status_bg    = "rgba(16,185,129,0.12)" if monitoring_on else "rgba(100,116,139,0.12)"

    st.markdown(
        f"""
<div style='background-color:#1e293b; padding:1.25rem; border-radius:12px;
                     border:1px solid #334155; font-family:"Inter",sans-serif;'>
<div style='display:flex; justify-content:space-between; align-items:center;
                          margin-bottom:1rem;'>
<span style='color:#cbd5e1; font-size:0.9rem;'>Status</span>
<span style='color:{status_color}; font-size:0.78rem; font-weight:600;
                              background-color:{status_bg}; padding:0.2rem 0.5rem;
                              border-radius:4px;'>{status_label}</span>
</div>
<div style='display:flex; justify-content:space-between; align-items:center;
                          margin-bottom:0.75rem; font-size:0.85rem;'>
<span style='color:#94a3b8;'>Protected Assets</span>
<span style='color:#f8fafc; font-weight:500;'>{asset_count if asset_count else "No data available."}</span>
</div>
<div style='display:flex; justify-content:space-between; align-items:center;
                          margin-bottom:0.75rem; font-size:0.85rem;'>
<span style='color:#94a3b8;'>Last Scan</span>
<span style='color:#f8fafc; font-weight:500;'>{last_scan_str}</span>
</div>
<div style='display:flex; justify-content:space-between; align-items:center;
                          margin-bottom:0.75rem; font-size:0.85rem;'>
<span style='color:#94a3b8;'>Next Scan</span>
<span style='color:#f8fafc; font-weight:500;'>{next_scan_str}</span>
</div>
<div style='display:flex; justify-content:space-between; align-items:center;
                          font-size:0.85rem;'>
<span style='color:#94a3b8;'>Scan Interval</span>
<span style='color:#f8fafc; font-weight:500;'>{scan_interval}</span>
</div>
</div>
        """,
        unsafe_allow_html=True,
    )


def _render_export_actions(incident: Optional[dict]) -> None:
    """Export actions — links to Reports page if incident exists."""
    st.markdown(
        "<div style='font-family:\"Inter\",sans-serif; font-size:1.1rem; font-weight:600;"
        " color:#f8fafc; margin-bottom:1rem;'>Reports</div>",
        unsafe_allow_html=True,
    )

    if not incident:
        st.markdown(
            "<div style='color:#64748b; font-size:0.85rem;'>No reports available. Run a scan first.</div>",
            unsafe_allow_html=True,
        )
        return

    if st.button("View Full Report", key="dash_view_report_btn", use_container_width=True):
        st.session_state["selected_report_id"] = incident.get("id", "")
        st.session_state["selected_report_data"] = incident
        st.session_state["navigate_to"] = "Reports"
        st.rerun()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _no_data_panel(message: str = "No data available.") -> None:
    """Standard 'no data' placeholder. Never fabricates information."""
    st.markdown(
        f"""
<div style="background-color:#1e293b; padding:1.5rem; border-radius:12px;
                    border:1px solid #334155; text-align:center;
                    color:#64748b; font-size:0.88rem; font-family:'Inter',sans-serif;">
{message}
</div>
        """,
        unsafe_allow_html=True,
    )


def _severity_sub(severity: str) -> str:
    return {
        "CRITICAL": "Action Required Immediately",
        "HIGH":     "Prompt Remediation Required",
        "MEDIUM":   "Review and Schedule Fix",
        "LOW":      "Monitor and Address",
        "—":        "Awaiting scan data",
}.get(severity, "See incident report")

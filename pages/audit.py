"""
pages/audit.py — Audit Log page.
Displays a chronological log of user and threat actions with filtering options.
"""

from __future__ import annotations

import streamlit as st
from firebase import db


def render() -> None:
    """Render the Audit Log page."""
    
    # Page Header
    st.markdown(
        """
        <div style="margin-bottom: 2rem;">
            <span style="font-size: 0.8rem; color: #00D4FF; text-transform: uppercase; letter-spacing: 0.15em; font-weight: 600;">System Integrity Logs</span>
            <h1 style="margin: 0; font-family: 'Space Grotesk', sans-serif;">Audit Timeline</h1>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    # Enforce role logic
    role = st.session_state.get("role", "analyst")
    is_admin = role.lower() in ("admin", "lead analyst")
    
    if not is_admin:
        st.error("🔒 Security Alert: Admin privilege required to view raw system audit trail logs.")
        st.info("Please request access from your SentinelAI system administrator.")
        return

    # Fetch logs from Firestore
    logs = db.get_audit_logs()
    
    # Render filter controls
    filters = _render_filters(logs)
    
    # Render table
    _render_log_table(logs, filters)


# ── Section Renderers ─────────────────────────────────────────────────────────

def _render_filters(logs: list[dict]) -> dict:
    """Render filter controls (user, action type). Returns filter dict."""
    st.markdown("### Log Filter Criteria")
    cards_col, filter_col = st.columns([0.3, 0.7])
    
    # Generate filter values dynamically from the logs
    unique_users = sorted(list({log.get("uid", "Unknown") for log in logs if log.get("uid")}))
    unique_actions = sorted(list({log.get("action", "Unknown") for log in logs if log.get("action")}))
    
    filters = {}
    
    with cards_col:
        st.markdown(
            f"""
            <div class="glass-panel" style="padding: 1rem !important; margin-bottom: 0px !important;">
                <span style="font-size: 0.8rem; color:#94A3B8;">AUDITED SYSTEMS</span><br>
                <b style="font-size: 1.4rem; color: #00D4FF;">{len(logs)} Events</b>
            </div>
            """, 
            unsafe_allow_html=True
        )
        
    with filter_col:
        c1, c2 = st.columns(2)
        with c1:
            filters["user"] = st.selectbox(
                "Filter by Actor",
                options=["All Actors"] + unique_users,
                key="audit_user_filter"
            )
        with c2:
            filters["action"] = st.selectbox(
                "Filter by Action Type",
                options=["All Actions"] + unique_actions,
                key="audit_action_filter"
            )
            
    st.markdown("<br>", unsafe_allow_html=True)
    return filters


def _render_log_table(logs: list[dict], filters: dict) -> None:
    """Render audit log entries as a paginated table."""
    st.markdown("### Chronological Audit Event Trail")
    
    # Filter calculation logic
    filtered_logs = logs
    if filters["user"] != "All Actors":
        filtered_logs = [l for l in filtered_logs if l.get("uid") == filters["user"]]
    if filters["action"] != "All Actions":
        filtered_logs = [l for l in filtered_logs if l.get("action") == filters["action"]]

    # Table Container
    st.markdown(
        """
        <div class="glass-panel" style="padding: 1rem !important;">
            <div style="display: flex; justify-content: space-between; border-bottom: 2px solid rgba(0, 212, 255, 0.15); padding-bottom: 0.5rem; margin-bottom: 0.5rem; font-weight: 600; font-size: 0.85rem; color: #94A3B8;">
                <span style="flex: 1.5;">ACTOR / UID</span>
                <span style="flex: 1.5; text-align: center;">ACTION TYPE</span>
                <span style="flex: 2; text-align: center;">TARGET OBJECT</span>
                <span style="flex: 1; text-align: center;">IP ADDRESS</span>
                <span style="flex: 1; text-align: right;">TIMESTAMP</span>
            </div>
        """,
        unsafe_allow_html=True
    )
    
    if not filtered_logs:
        st.markdown(
            """
            <div style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                No events matching search filter values found.
            </div>
            """, 
            unsafe_allow_html=True
        )
    else:
        for log in filtered_logs:
            # Color event indicators based on action or status if present
            action = log.get("action", "").upper()
            status = log.get("status", "")
            
            if "FAIL" in action or status == "failed":
                status_color = "#FF4C4C"
            elif "ALERT" in action or status == "alert":
                status_color = "#FF8C00"
            else:
                status_color = "#00E5A0"
            
            ts = log.get("timestamp")
            timestamp_str = ts.strftime("%b %d, %H:%M:%S") if hasattr(ts, "strftime") else str(ts)
            
            st.markdown(
                f"""
                <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255, 255, 255, 0.05); padding: 0.75rem 0; font-size: 0.85rem;">
                    <div style="flex: 1.5; font-weight: 500; color: #F1F5F9;">
                        {log.get('uid', 'Unknown')}
                    </div>
                    <div style="flex: 1.5; text-align: center;">
                        <span style="color: {status_color}; font-weight: 600;">{log.get('action', 'Unknown')}</span>
                    </div>
                    <div style="flex: 2; text-align: center; color: #94A3B8; word-break: break-all;">
                        {log.get('target', 'Unknown')}
                    </div>
                    <div style="flex: 1; text-align: center; color: #64748B;">
                        {log.get('ip', '')}
                    </div>
                    <div style="flex: 1; text-align: right; color: #475569; font-size: 0.75rem;">
                        {timestamp_str}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
            
    st.markdown("</div>", unsafe_allow_html=True)

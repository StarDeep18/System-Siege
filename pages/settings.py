"""
pages/settings.py — Settings configuration page.
Allows updating simulated analyst details, AI model selections, and threshold adjustments.
"""

from __future__ import annotations

import streamlit as st
from components import cards


def render() -> None:
    """Render the Settings page."""
    
    # Page Header
    st.markdown(
        """
        <div style="margin-bottom: 2rem;">
            <span style="font-size: 0.8rem; color: #00D4FF; text-transform: uppercase; letter-spacing: 0.15em; font-weight: 600;">Control Center</span>
            <h1 style="margin: 0; font-family: 'Space Grotesk', sans-serif;">System Settings</h1>
        </div>
        """,
        unsafe_allow_html=True
    )

    col_left, col_right = st.columns([0.6, 0.4])

    with col_left:
        st.markdown("### Profile Settings")
        _render_profile_settings()
        
        st.markdown("### Threat Threshold Configurations")
        _render_threshold_settings()

    with col_right:
        st.markdown("### Artificial Intelligence Nodes")
        _render_ai_settings()


# ── Section Renderers ─────────────────────────────────────────────────────────

def _render_profile_settings() -> None:
    """Render configuration inputs for analyst profile details."""
    cards.glass_container()
    
    current_email = st.session_state.get("user_email", "analyst@sentinel.ai")
    current_role = st.session_state.get("role", "Lead Analyst")

    email = st.text_input("Profile Email Address", value=current_email, key="settings_email_input", disabled=True)
    role = st.text_input("Active Role Context", value=current_role.capitalize(), key="settings_role_input", disabled=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
        
    st.markdown("</div>", unsafe_allow_html=True)


def _render_threshold_settings() -> None:
    """Render sliding controls for scanner and detection engine sensitivity."""
    cards.glass_container()
    
    st.slider(
        "Defacement Similarity Threshold",
        min_value=0.05,
        max_value=0.60,
        value=0.30,
        step=0.05,
        help="Similarity score offset before flag triggering. Recommended defaults: 0.30"
    )
    
    st.slider(
        "Critical Risk Score Margin",
        min_value=10,
        max_value=60,
        value=30,
        step=5,
        help="Minimum threshold index triggering instant page pager alert notifications."
    )
    
    st.checkbox("Force HTTPS Redirection Checks", value=True)
    st.checkbox("Enable Real-time DNS Resolution Cache Check", value=True)
    
    st.markdown("</div>", unsafe_allow_html=True)


def _render_ai_settings() -> None:
    """Render selector settings for explainability/story models."""
    cards.glass_container()
    
    st.selectbox(
        "LLM Core Node Engine",
        options=["gemini-1.5-flash (Recommended)", "gemini-1.5-pro", "cortex-custom-hybrid"],
        index=0,
        key="settings_ai_model_select"
    )
    
    st.text_area(
        "AI Behavior Sandbox Prompts",
        value="System Instructions: Treat target as structured reports. Do not interpret unless evidence matches report indexes.",
        disabled=True
    )
    
    st.markdown("</div>", unsafe_allow_html=True)

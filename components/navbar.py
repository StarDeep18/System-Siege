"""
components/navbar.py — Sidebar navigation.
Displays the brand header, pages options, authenticated profile summary, and logs user out.
"""

from __future__ import annotations

import streamlit as st


# ── Public Interface ──────────────────────────────────────────────────────────

def render() -> None:
    """Render the custom sidebar navigation."""
    
    # Build dynamic navigation items
    nav_items = [
        ("🏠", "Dashboard"),
        ("🔍", "Scan Website"),
        ("🖥️", "Asset Management"),
        ("📄", "Incident Reports"),
        ("👁️", "Visual Diff"),
        ("📋", "Audit Timeline"),
        ("⚙️", "Settings"),
    ]
    
    if st.session_state.get("role") == "admin":
        nav_items.append(("🛡️", "Admin Panel"))
        
    with st.sidebar:
        # Brand Header
        st.markdown(
            """
            <div style="padding: 1rem 0; text-align: center; border-bottom: 1px solid rgba(0, 212, 255, 0.15); margin-bottom: 1.5rem;">
                <h2 style="margin: 0; color: #00D4FF; font-family: 'Space Grotesk', sans-serif; letter-spacing: 0.05em; font-size: 1.6rem;">
                    🛡️ SENTINEL<span style="color:#F1F5F9;">AI</span>
                </h2>
                <span style="font-size: 0.65rem; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.2em;">
                    Security Operations Center
                </span>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Navigation Buttons
        st.markdown(
            '<div style="font-family: \'Space Grotesk\', sans-serif; font-size: 0.85rem; color: #94A3B8; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.1em;">Operations</div>', 
            unsafe_allow_html=True
        )
        
        # Track selected navigation item in session state
        if "active_page" not in st.session_state:
            st.session_state["active_page"] = "Dashboard"

        for icon, page_name in nav_items:
            is_active = st.session_state["active_page"] == page_name
            # Render a nice cyber-styled navigation button
            btn_label = f"{icon}  {page_name}"
            
            # Highlight active button visually
            if is_active:
                st.markdown(
                    f"""
                    <div style="background: rgba(0, 212, 255, 0.15); border-left: 3px solid #00D4FF; border-radius: 4px; padding: 0.5rem 1rem; margin-bottom: 0.4rem; color: #F1F5F9; font-weight: 500; cursor: pointer;">
                        {btn_label}
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                if st.button(btn_label, key=f"nav_btn_{page_name}"):
                    st.session_state["active_page"] = page_name
                    st.rerun()

        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown("<hr style='border-color: rgba(0, 212, 255, 0.15); margin: 1rem 0;'>", unsafe_allow_html=True)

        # User Profile Summary
        _render_user_panel()


# ── Private Helpers ───────────────────────────────────────────────────────────

def _render_user_panel() -> None:
    """Render the current user profile summary at the bottom of the sidebar."""
    email = st.session_state.get("email", "analyst@sentinel.ai")
    role = st.session_state.get("role", "analyst").title()

    st.markdown(
        f"""
        <div style="padding: 0.5rem; border-radius: 8px; background: rgba(13, 20, 33, 0.4); border: 1px solid rgba(0, 212, 255, 0.08); margin-bottom: 1rem;">
            <div style="font-size: 0.8rem; font-weight: 600; color: #F1F5F9; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                {email}
            </div>
            <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 0.25rem;">
                <span class="cyber-badge badge-neon" style="font-size: 0.6rem; padding: 0.1rem 0.4rem;">
                    {role}
                </span>
                <span style="font-size: 0.65rem; color: #00E5A0;">● Online</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    if st.button("🚪 Logout", key="logout_btn"):
        # Fully clear session state to wipe all traces of the previous user
        st.session_state.clear()
        st.rerun()

"""
SentinelAI SOC — Entry Point
Handles custom CSS styling injections, navigation, and page routing.
"""

from __future__ import annotations

import streamlit as st
from dotenv import load_dotenv

from components import navbar
from firebase import config as firebase_config
import components.auth as auth
import pages.dashboard as dashboard
import pages.scanner as scanner
import pages.assets as assets
import pages.reports as reports
import pages.audit as audit
import pages.settings as settings
import pages.admin as admin

# ── Theme CSS Loader ──────────────────────────────────────────────────────────

def _load_custom_css() -> None:
    """Inject custom styles/theme.css directly into the Streamlit app header."""
    try:
        with open("styles/theme.css", "r") as f:
            css = f.read()
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        pass


# ── Bootstrap ─────────────────────────────────────────────────────────────────

load_dotenv()

st.set_page_config(
    page_title="SentinelAI SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Load global CSS theme variables and custom visual classes
_load_custom_css()

# Initialize Firebase Admin SDK
try:
    firebase_config.initialise()
except Exception as e:
    st.error(f"⚠️ Firebase Initialization Error: {e}")
    st.info("Make sure FIREBASE_SERVICE_ACCOUNT_JSON is set correctly in your .env file.")
    st.stop()


# ── Session State Defaults ────────────────────────────────────────────────────

def _init_session() -> None:
    if "active_page" not in st.session_state:
        st.session_state["active_page"] = "Dashboard"


# ── Routing ───────────────────────────────────────────────────────────────────

def _route() -> None:
    """Render the active page based on session state selection."""
    page = st.session_state.get("active_page", "Dashboard")
    
    if page == "Dashboard":
        dashboard.render()
    elif page == "Scan Website":
        scanner.render()
    elif page == "Asset Management":
        assets.render()
    elif page == "Incident Reports":
        reports.render()
    elif page == "Audit Timeline":
        audit.render()
    elif page == "Settings":
        settings.render()
    elif page == "Admin Panel":
        admin.render()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    _init_session()

    # Enforce Authentication
    if not st.session_state.get("uid"):
        auth.render()
        return

    # Left-hand side customizable sidebar navigation
    navbar.render()
    
    # Active page display panel (main section)
    _route()


if __name__ == "__main__":
    main()

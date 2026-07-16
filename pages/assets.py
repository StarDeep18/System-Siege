"""
pages/assets.py — Asset Management page.
Allows users to add, view, and delete monitored URLs.
"""

from __future__ import annotations

import streamlit as st
from components import cards
from firebase import db


def render() -> None:
    """Render the Assets page."""
    
    # Page Header
    st.markdown(
        """
        <div style="margin-bottom: 2rem;">
            <span style="font-size: 0.8rem; color: #00D4FF; text-transform: uppercase; letter-spacing: 0.15em; font-weight: 600;">Resource Inventory</span>
            <h1 style="margin: 0; font-family: 'Space Grotesk', sans-serif;">Asset Management</h1>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Main Grid Layout
    col_left, col_right = st.columns([0.7, 0.3])

    with col_left:
        st.markdown("### Protected Web Resources")
        _render_asset_list()

    with col_right:
        st.markdown("### Register New Asset")
        _render_add_asset_form()


# ── Section Renderers ─────────────────────────────────────────────────────────

def _render_add_asset_form() -> None:
    """Render the Add Asset form (URL + display name)."""
    cards.glass_container()
    
    # Form input fields
    name = st.text_input("Asset Name", placeholder="e.g. Corporate Storefront", key="new_asset_name", max_chars=2000)
    url = st.text_input("Target URL", placeholder="https://example.com", key="new_asset_url", max_chars=2000)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    if st.button("➕ Confirm Registry", key="confirm_register_asset"):
        if name and url:
            uid = st.session_state.get("uid")
            if uid:
                db.add_asset(uid, url, name)
                
                # Log the addition
                db.log_action(uid, "ADD_ASSET", url)
                
                st.success(f"Asset '{name}' successfully queued for Verification Scan!")
                st.info("The Security Validation Layer is verifying domain ownership.")
                st.rerun()
            else:
                st.error("Authentication required to add an asset.")
        else:
            st.error("Please fill in both fields.")
            
    st.markdown("</div>", unsafe_allow_html=True)


def _render_asset_list() -> None:
    """Render all assets owned by the current user as cards."""
    uid = st.session_state.get("uid")
    if not uid:
        st.warning("Please log in to view your assets.")
        return
        
    # Load assets from Firestore
    assets_list = db.get_assets(uid)
    
    if not assets_list:
        st.info("No assets registered. Add an asset to get started.")
        return
    
    # Render cards in a responsive grid
    col1, col2 = st.columns(2)
    
    for i, asset in enumerate(assets_list):
        # Alternate columns
        target_col = col1 if i % 2 == 0 else col2
        
        with target_col:
            scan_clicked, delete_clicked = cards.asset_card(asset, key_prefix="manage")
            
            if scan_clicked:
                # Store target asset details in session state and redirect
                st.session_state["target_scan_url"] = asset.get("url", "")
                st.session_state["active_page"] = "Scan Website"
                st.rerun()
                
            if delete_clicked:
                db.delete_asset(uid, asset["id"])
                
                # Log the deletion
                db.log_action(uid, "DELETE_ASSET", asset.get("url", ""))
                
                st.toast(f"Initiated removal process for asset: {asset.get('name', 'Unknown')}", icon="🗑️")
                st.info(f"Removed {asset.get('name', 'Unknown')} ({asset.get('url', '')}) from database.")
                st.rerun()

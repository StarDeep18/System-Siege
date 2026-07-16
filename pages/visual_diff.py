"""
pages/visual_diff.py — Scan History & Visual Diff.
Fetches past snapshots and performs side-by-side visual image and HTML diffing.
"""

from __future__ import annotations

import difflib
import io
import streamlit as st
import numpy as np
from PIL import Image
from firebase_admin import firestore

def render() -> None:
    """Render the Scan History & Visual Diff page."""
    
    st.markdown(
        """
        <div style="margin-bottom: 2rem;">
            <div style="font-size: 0.8rem; color: #64748b; font-weight: 500;
                        text-transform: uppercase; letter-spacing: 0.05em;
                        font-family: 'Inter', sans-serif; margin-bottom: 0.25rem;">
                Historical Analysis
            </div>
            <h1 style="margin: 0; font-family: 'Inter', sans-serif;
                       font-weight: 600; font-size: 1.8rem; color: #f8fafc;">
                Scan History & Visual Diff
            </h1>
        </div>
        """,
        unsafe_allow_html=True,
    )

    db = firestore.client()

    # 1. Fetch sites
    try:
        sites_ref = db.collection("sites").stream()
        sites = {site.id: site.to_dict() for site in sites_ref}
    except Exception as e:
        st.error(f"Failed to fetch sites from Firestore: {e}")
        return

    if not sites:
        st.info("No monitored sites found. Please add a site first.")
        return

    # Create options mapping Name -> ID
    site_options = {data.get("name", id): id for id, data in sites.items()}
    
    selected_site_name = st.selectbox(
        "Select Monitored Website", 
        options=list(site_options.keys())
    )
    
    if not selected_site_name:
        return
        
    site_id = site_options[selected_site_name]

    # 2. Fetch Snapshots
    try:
        snapshots_ref = db.collection("snapshots").where("site_id", "==", site_id).order_by("captured_at", direction=firestore.Query.DESCENDING).stream()
        snapshots = [doc.to_dict() | {"id": doc.id} for doc in snapshots_ref]
    except Exception as e:
        st.error(f"Failed to fetch snapshots: {e}")
        return

    if len(snapshots) < 2:
        st.warning("Not enough snapshots found to perform a diff. At least 2 snapshots are required.")
        return

    st.markdown("### Snapshot Comparison")
    
    # Create options mapping Timestamp -> Snapshot
    snap_options = {}
    for snap in snapshots:
        ts = snap.get("captured_at")
        if hasattr(ts, "strftime"):
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            ts_str = str(ts)
        snap_options[f"{ts_str} ({snap['id']})"] = snap

    col_base, col_curr = st.columns(2)
    with col_base:
        base_label = st.selectbox("Baseline Snapshot (Older)", options=list(snap_options.keys()), index=1)
    with col_curr:
        curr_label = st.selectbox("Comparison Snapshot (Newer)", options=list(snap_options.keys()), index=0)

    base_snap = snap_options[base_label]
    curr_snap = snap_options[curr_label]

    if st.button("Generate Visual Diff", type="primary"):
        _render_diff(base_snap, curr_snap)
        
    # 3. Fetch Alerts
    st.markdown("### Recent Alerts")
    try:
        alerts_ref = db.collection("alerts").where("site_id", "==", site_id).stream()
        alerts = [doc.to_dict() for doc in alerts_ref]
    except Exception as e:
        st.error(f"Failed to fetch alerts: {e}")
        alerts = []

    if not alerts:
        st.info("No alerts recorded for this site.")
    else:
        # Sort manually by created_at descending just in case
        alerts.sort(key=lambda x: str(x.get("created_at", "")), reverse=True)
        for alert in alerts:
            _render_alert(alert)


def _render_diff(base_snap: dict, curr_snap: dict) -> None:
    """Compare screenshots and HTML, then render the results."""
    st.markdown("---")
    
    # ── Pixel-by-Pixel Image Diffing ──
    st.markdown("#### Visual Pixel Difference")
    
    base_img_path = base_snap.get("screenshot_path")
    curr_img_path = curr_snap.get("screenshot_path")
    
    if base_img_path and curr_img_path:
        try:
            with Image.open(base_img_path) as img1, Image.open(curr_img_path) as img2:
                # Ensure same size for numpy subtraction
                if img1.size != img2.size:
                    # Resize img2 to match img1
                    img2 = img2.resize(img1.size)
                
                # Convert to numpy arrays
                arr1 = np.array(img1.convert("RGB")).astype(np.int16)
                arr2 = np.array(img2.convert("RGB")).astype(np.int16)
                
                # Absolute difference
                diff_arr = np.abs(arr2 - arr1)
                
                # Calculate % pixels changed (threshold > 15 per channel)
                # A pixel is "changed" if any of its RGB channels changed > 15
                changed_mask = np.any(diff_arr > 15, axis=-1)
                total_pixels = arr1.shape[0] * arr1.shape[1]
                changed_pixels = np.sum(changed_mask)
                diff_pct = (changed_pixels / total_pixels) * 100
                
                # Generate brightened diff image
                # Multiply diff by 5 and clip to 255
                bright_diff = np.clip(diff_arr * 5, 0, 255).astype(np.uint8)
                diff_img = Image.fromarray(bright_diff)
                
                # Render metrics
                st.metric(label="Visual Modification Rate", value=f"{diff_pct:.2f}%", delta=f"{diff_pct:.2f}%", delta_color="inverse")
                
                # Render images side-by-side
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.image(img1, caption="Baseline Snapshot", use_container_width=True)
                with c2:
                    st.image(img2, caption="Comparison Snapshot", use_container_width=True)
                with c3:
                    st.image(diff_img, caption="Highlighted Differences", use_container_width=True)
                    
        except Exception as e:
            st.error(f"Error processing image diff: {e}")
    else:
        st.warning("Screenshot paths not found in snapshot data.")


    # ── HTML Unified Diff ──
    st.markdown("#### Source Code Unified Diff")
    
    base_html_path = base_snap.get("html_path")
    curr_html_path = curr_snap.get("html_path")
    
    if base_html_path and curr_html_path:
        try:
            with open(base_html_path, "r", encoding="utf-8") as f1, open(curr_html_path, "r", encoding="utf-8") as f2:
                base_lines = f1.readlines()
                curr_lines = f2.readlines()
                
            diff = list(difflib.unified_diff(
                base_lines, 
                curr_lines, 
                fromfile='baseline.html', 
                tofile='comparison.html'
            ))
            
            if diff:
                added = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
                removed = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))
                
                st.markdown(f"**Lines Added:** `{added}` | **Lines Removed:** `{removed}`")
                
                # Show diff in code block
                st.code("".join(diff), language="diff")
            else:
                st.success("No source code differences detected.")
                
        except Exception as e:
            st.error(f"Error processing HTML diff: {e}")
    else:
        st.warning("HTML file paths not found in snapshot data.")


def _render_alert(alert: dict) -> None:
    """Render an individual alert in a styled expander."""
    severity = alert.get("severity", "LOW").upper()
    title = alert.get("title", "Untitled Alert")
    desc = alert.get("description", "")
    ai_analysis = alert.get("ai_analysis", "")
    ai_rec = alert.get("ai_recommendation", "")
    ts = alert.get("created_at", "")
    
    if hasattr(ts, "strftime"):
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        ts_str = str(ts)
        
    color_map = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }
    icon = color_map.get(severity, "⚪")
    
    with st.expander(f"{icon} {severity} - {title} [{ts_str}]"):
        st.markdown(f"**Description:** {desc}")
        if ai_analysis:
            st.markdown(f"**AI Analysis:** {ai_analysis}")
        if ai_rec:
            st.markdown(f"**AI Recommendation:** {ai_rec}")
        
        diff_pct = alert.get("pixel_diff_pct")
        if diff_pct is not None:
            st.markdown(f"**Visual Change Detected:** `{diff_pct:.2f}%`")

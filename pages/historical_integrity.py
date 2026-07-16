"""
pages/historical_integrity.py — Historical Integrity Analysis.

Data flow (fully uid-scoped):
  current_user.uid
    → assets (uid-filtered)
    → selected asset
    → snapshots (uid + asset_id filtered)
    → Snapshot Comparison

No snapshot from another user will ever appear here.
"""

from __future__ import annotations

import difflib
import io
import os
import streamlit as st
import numpy as np
from PIL import Image

from firebase import db


def render() -> None:
    """Render the Historical Integrity Analysis page."""

    st.markdown(
        """
        <div style="margin-bottom: 2rem;">
            <div style="font-size: 0.8rem; color: #00D4FF; font-weight: 500;
                        text-transform: uppercase; letter-spacing: 0.05em;
                        font-family: 'Space Grotesk', sans-serif; margin-bottom: 0.25rem;">
                Executive Documentation
            </div>
            <h1 style="margin: 0; font-family: 'Space Grotesk', sans-serif;
                       font-weight: 600; font-size: 1.8rem; color: #f8fafc;">
                Historical Integrity Analysis
            </h1>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Auth Guard ────────────────────────────────────────────────────────────
    uid = st.session_state.get("uid")
    if not uid:
        st.error("Authentication required. Please log in to view your scan history.")
        return

    # ── Direct Link Scan ──────────────────────────────────────────────────────
    st.markdown("### Direct Link Scan")
    col_url, col_btn = st.columns([0.8, 0.2])
    with col_url:
        adhoc_url = st.text_input(
            "Enter URL to scan and add to monitoring",
            placeholder="https://example.com",
            label_visibility="collapsed"
        )
    with col_btn:
        if st.button("Scan Now", type="primary", use_container_width=True):
            if adhoc_url:
                import pages.scanner as scanner
                scanner._run_scan(adhoc_url.strip())
                st.rerun()

    # ── 1. Load uid-scoped Assets ─────────────────────────────────────────────
    try:
        assets = db.get_assets(uid)
    except Exception as e:
        st.error(f"Failed to fetch your assets: {e}")
        return

    if not assets:
        st.info("No monitoring history found. Run a scan to create your first snapshot.")
        return

    # Build mapping: display_name → asset doc
    asset_map = {
        f"{a.get('name', a.get('url', a['id']))}": a
        for a in assets
    }

    st.markdown("### Protected Assets")
    
    selected_name = st.selectbox(
        "Select Monitored Website",
        options=list(asset_map.keys()),
        label_visibility="collapsed"
    )

    if not selected_name:
        return

    selected_asset = asset_map[selected_name]
    asset_id = selected_asset["id"]
    asset_url = selected_asset.get("url", "")
    
    # ── Monitoring Scheduler Controls ──
    st.markdown("### Monitoring Scheduler Configuration")
    
    m_enabled = selected_asset.get("monitoring_enabled", False)
    m_interval = selected_asset.get("monitoring_interval_minutes", 1440)
    
    # Map minutes back to selection labels
    minutes_map = {
        15: "15 minutes",
        30: "30 minutes",
        60: "60 minutes",
        360: "6 hours",
        720: "12 hours",
        1440: "24 hours"
    }
    
    default_label = minutes_map.get(m_interval, "Custom")
    options = ["15 minutes", "30 minutes", "60 minutes", "6 hours", "12 hours", "24 hours", "Custom"]
    
    try:
        default_index = options.index(default_label)
    except ValueError:
        default_index = 6 # Custom
        
    c_status, c_control = st.columns([0.4, 0.6])
    
    with c_status:
        st.markdown("**Status:**")
        if m_enabled:
            st.markdown("<span style='color:#10b981; font-weight:600; font-size:1.1rem;'>● ACTIVE</span>", unsafe_allow_html=True)
            last_run = selected_asset.get("last_scanned")
            next_run = selected_asset.get("next_scheduled_scan_at")
            if last_run:
                st.write(f"Last Scan: {last_run.strftime('%Y-%m-%d %H:%M UTC')}")
            if next_run:
                st.write(f"Next Scan: {next_run.strftime('%Y-%m-%d %H:%M UTC')}")
        else:
            st.markdown("<span style='color:#64748b; font-weight:600; font-size:1.1rem;'>● INACTIVE</span>", unsafe_allow_html=True)
            
    with c_control:
        enable_monitoring = st.checkbox("Enable Continuous Monitoring", value=m_enabled)
        interval_choice = st.selectbox("Scan Interval", options=options, index=default_index)
        
        custom_mins = m_interval
        if interval_choice == "Custom":
            custom_mins = st.number_input("Custom Interval (minutes)", min_value=1, value=m_interval if m_interval not in minutes_map else 5)
            
        if st.button("Save Monitoring Configuration", type="primary", use_container_width=True):
            # Calculate interval minutes
            choice_to_mins = {
                "15 minutes": 15,
                "30 minutes": 30,
                "60 minutes": 60,
                "6 hours": 360,
                "12 hours": 720,
                "24 hours": 1440
            }
            chosen_mins = choice_to_mins.get(interval_choice, custom_mins)
            
            db_client = db.get_db()
            asset_ref = db_client.collection(db.ASSETS).document(asset_id)
            
            from datetime import timedelta
            next_scan_time = datetime.utcnow() + timedelta(minutes=chosen_mins) if enable_monitoring else None
            
            asset_ref.update({
                "monitoring_enabled": enable_monitoring,
                "monitoring_interval_minutes": chosen_mins,
                "next_scheduled_scan_at": next_scan_time
            })
            
            st.success("Monitoring schedule updated!")
            time.sleep(0.5)
            st.rerun()

    if st.button("Trigger Manual Scan Now", key="trigger_schedule"):
        st.info("Triggering background scan using Playwright and Risk Engine...")
        import pages.scanner as scanner
        if asset_url:
            scanner._run_scan(asset_url)
            st.rerun()

    # ── 2. Load uid + asset-scoped Snapshots ──────────────────────────────────
    try:
        snapshots = db.get_snapshots(uid, asset_id=asset_id)
    except Exception as e:
        st.error(f"Failed to fetch snapshots: {e}")
        return

    if len(snapshots) < 2:
        st.warning(
            "Not enough snapshots found for this asset. "
            "At least 2 scans are required to perform a diff. "
            "Run another scan above to generate a second snapshot."
        )
        return

    # ── 3. Snapshot Comparison ────────────────────────────────────────────────
    st.markdown("### Snapshot Comparison")

    snap_options = {}
    for snap in snapshots:
        ts = snap.get("timestamp") or snap.get("captured_at")
        if hasattr(ts, "strftime"):
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            ts_str = str(ts)[:19] if ts else "Unknown time"
        snap_options[f"{ts_str} ({snap['id'][:8]}…)"] = snap

    labels = list(snap_options.keys())
    col_base, col_curr = st.columns(2)
    with col_base:
        base_label = st.selectbox("Baseline Snapshot (Older)", options=labels, index=min(1, len(labels) - 1))
    with col_curr:
        curr_label = st.selectbox("Comparison Snapshot (Newer)", options=labels, index=0)

    base_snap = snap_options[base_label]
    curr_snap = snap_options[curr_label]

    if st.button("Generate Visual Diff", type="primary"):
        _render_diff(base_snap, curr_snap)

    # ── 4. Recent Alerts (uid-scoped via asset_id in scans) ───────────────────
    st.markdown("### Recent Alerts")
    try:
        scans = db.get_scans(uid, asset_id=asset_id, limit=10)
        alerts = [s for s in scans if s.get("defacement_detected") or s.get("severity") in ("HIGH", "CRITICAL")]
    except Exception as e:
        st.error(f"Failed to fetch recent alerts: {e}")
        alerts = []

    if not alerts:
        st.info("No alerts recorded for this asset.")
    else:
        for alert in alerts:
            _render_alert(alert)


def _render_diff(base_snap: dict, curr_snap: dict) -> None:
    """Compare screenshots and HTML, then render the results."""
    st.markdown("---")

    # ── Diff Statistics ──
    st.markdown("### Diff Statistics")

    dom1 = base_snap.get("dom_fingerprint", "N/A")
    dom2 = curr_snap.get("dom_fingerprint", "N/A")
    dom_match = "✅ Matched" if dom1 == dom2 else "❌ Altered"

    txt1 = base_snap.get("text_fingerprint", "N/A")
    txt2 = curr_snap.get("text_fingerprint", "N/A")
    text_match = "✅ Matched" if txt1 == txt2 else "❌ Altered"

    st.markdown(f"**DOM Structure Hash:** {dom_match}")
    st.markdown(f"**Text Content Hash:** {text_match}")
    st.markdown("<br>", unsafe_allow_html=True)

    # ── Pixel-by-Pixel Image Diffing ──
    st.markdown("### Visual Evidence")

    base_img_path = base_snap.get("screenshot_path")
    curr_img_path = curr_snap.get("screenshot_path")

    if base_img_path and curr_img_path and os.path.exists(base_img_path) and os.path.exists(curr_img_path):
        try:
            with Image.open(base_img_path) as img1, Image.open(curr_img_path) as img2:
                if img1.size != img2.size:
                    img2 = img2.resize(img1.size)

                arr1 = np.array(img1.convert("RGB")).astype(np.int16)
                arr2 = np.array(img2.convert("RGB")).astype(np.int16)
                diff_arr = np.abs(arr2 - arr1)

                changed_mask = np.any(diff_arr > 15, axis=-1)
                diff_pct = (np.sum(changed_mask) / (arr1.shape[0] * arr1.shape[1])) * 100
                sim_score = 100 - diff_pct

                bright_diff = np.clip(diff_arr * 5, 0, 255).astype(np.uint8)
                diff_img = Image.fromarray(bright_diff)

                st.metric(
                    label="Similarity Score",
                    value=f"{sim_score:.2f}%",
                    delta=f"{-diff_pct:.2f}% Modification",
                    delta_color="inverse"
                )

                c1, c2, c3 = st.columns(3)
                with c1:
                    st.image(img1, caption="Baseline Snapshot", use_container_width=True)
                with c2:
                    st.image(img2, caption="Current Snapshot", use_container_width=True)
                with c3:
                    st.image(diff_img, caption="Pixel Difference", use_container_width=True)

        except Exception as e:
            st.error(f"Error processing image diff: {e}")
    else:
        st.warning("Screenshots not found locally. Did you run a scan with the Playwright engine enabled?")

    # ── HTML Unified Diff ──
    st.markdown("### HTML Difference")

    base_html_path = base_snap.get("html_path")
    curr_html_path = curr_snap.get("html_path")

    if base_html_path and curr_html_path and os.path.exists(base_html_path) and os.path.exists(curr_html_path):
        try:
            with open(base_html_path, "r", encoding="utf-8") as f1, open(curr_html_path, "r", encoding="utf-8") as f2:
                base_lines = f1.readlines()
                curr_lines = f2.readlines()

            diff = list(difflib.unified_diff(
                base_lines,
                curr_lines,
                fromfile="baseline.html",
                tofile="comparison.html"
            ))

            if diff:
                added = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
                removed = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))
                st.markdown(f"**Changed Elements:** `{added}` additions | `{removed}` removals")
                with st.expander("View Full HTML Diff", expanded=False):
                    st.code("".join(diff), language="diff")
            else:
                st.success("No source code differences detected.")

        except Exception as e:
            st.error(f"Error processing HTML diff: {e}")
    else:
        st.warning("HTML files not found locally.")


def _render_alert(alert: dict) -> None:
    """Render an individual alert entry."""
    severity = alert.get("severity", "LOW").upper()
    url = alert.get("url", alert.get("asset", "Unknown"))
    ts = alert.get("timestamp", "")

    if hasattr(ts, "strftime"):
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        ts_str = str(ts)[:19] if ts else "Unknown time"

    color_map = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }
    icon = color_map.get(severity, "⚪")

    with st.expander(f"{icon} {severity} — {url} [{ts_str}]"):
        score = alert.get("overall_security_score", alert.get("score", "—"))
        st.markdown(f"**Security Score:** {score}/100")
        summary = alert.get("executive_summary", alert.get("summary", ""))
        if summary:
            st.markdown(f"**Summary:** {summary}")

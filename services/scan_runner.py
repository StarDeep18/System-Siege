"""
services/scan_runner.py — Headless scan pipeline execution for scheduled monitoring.
Runs as a standalone process to prevent event loop / threading conflicts with Playwright.
"""

from __future__ import annotations

import argparse
import sys
import os
import time
from datetime import datetime, timezone, timedelta

# Adjust python path to allow importing from parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv
load_dotenv()

from firebase import config as firebase_config
from firebase import db
from security.url_validator import validate as validate_url
from evidence_engine.fetcher import fetch, FetchResult
from evidence_engine.models import (
    EvidenceError, ScanEvidence, RequestMetadata, HeaderEvidence, SSLEvidence,
    SnapshotEvidence, SnapshotMetadata, DiffEvidence, ScanMetrics, VulnerabilityFinding
)
from evidence_engine.headers import analyse as analyse_headers
from evidence_engine import ssl_checker
from evidence_engine import snapshot
from evidence_engine import diff
from evidence_engine import active_scanner
from risk_engine import engine as risk_engine
from ai import explainability
from ai import attack_story
from incident import builder as incident_builder
import numpy as np
from PIL import Image


def get_pixel_diff_pct(img_path1: str, img_path2: str) -> float:
    """Compute the visual pixel difference percentage between two screenshots."""
    if not img_path1 or not img_path2 or not os.path.exists(img_path1) or not os.path.exists(img_path2):
        return 0.0
    try:
        with Image.open(img_path1) as img1, Image.open(img_path2) as img2:
            if img1.size != img2.size:
                img2 = img2.resize(img1.size)
            arr1 = np.array(img1.convert("RGB")).astype(np.int16)
            arr2 = np.array(img2.convert("RGB")).astype(np.int16)
            diff_arr = np.abs(arr2 - arr1)
            changed_mask = np.any(diff_arr > 15, axis=-1)
            diff_pct = (np.sum(changed_mask) / (arr1.shape[0] * arr1.shape[1])) * 100
            return float(diff_pct)
    except Exception as e:
        print(f"Error computing pixel diff: {e}")
        return 0.0


def run_scan(url: str, uid: str, asset_id: str) -> None:
    """Execute the full 12-step scan pipeline headlessly."""
    firebase_config.initialise()
    
    print(f"Starting scheduled monitoring scan for {url} (UID: {uid}, Asset: {asset_id})")
    
    # 1. URL Validation
    try:
        validated_url = validate_url(url)
    except ValueError as e:
        print(f"URL validation failed: {e}")
        return

    # 2. Fetch
    result = fetch(validated_url)
    if isinstance(result, EvidenceError):
        print(f"Fetch failed: {result.message}")
        db.log_action(uid, "MONITOR_SCAN_FAILED", f"{url}: {result.message}")
        return

    # 3. Header Analysis
    header_findings = analyse_headers(result.headers)

    # 4. SSL Check
    ssl_result = ssl_checker.check(validated_url)

    # 5. Snapshot
    snap = snapshot.capture(result)

    # 6. Diff & Comparison against previous baseline
    prev_snaps = db.get_snapshots(uid, asset_id=asset_id, limit=1)
    pixel_diff_pct = 0.0
    
    if prev_snaps:
        prev_snap = snapshot.from_firestore_dict(prev_snaps[0])
        diff_result = diff.compare(prev_snap, snap)
        # Compute visual difference
        pixel_diff_pct = get_pixel_diff_pct(prev_snap.screenshot_path, snap.screenshot_path)
    else:
        diff_result = diff.compare(snap, snap)

    # 6.5. Active Penetration Testing
    active_result = active_scanner.run_active_scan(validated_url)

    # 7. Assemble Evidence
    tls_info = {}
    cert_info = {}
    if ssl_result:
        tls_info = {"protocol": ssl_result.protocol_version, "cipher": ssl_result.cipher_suite}
        cert_info = {
            "valid": ssl_result.valid,
            "days_until_expiry": ssl_result.days_until_expiry,
            "grade": ssl_result.grade,
            "issuer": ssl_result.issuer
        }

    evidence = ScanEvidence(
        metadata=RequestMetadata(
            status="SUCCESS",
            url=result.url,
            hostname=result.hostname,
            resolved_ip=result.resolved_ip,
            scan_duration=result.response_time,
        ),
        headers=HeaderEvidence(
            status_code=result.status_code,
            response_time=result.response_time,
            headers=result.headers,
            security_headers={f.header_name: f.value for f in header_findings if f.present}
        ),
        ssl=SSLEvidence(
            tls_information=tls_info,
            certificate_information=cert_info
        ),
        snapshot=SnapshotEvidence(
            snapshot_metadata=SnapshotMetadata(hash=snap.text_fingerprint, snapshot_size=len(snap.text_content))
        ),
        diff=DiffEvidence(
            change_type="NONE" if not prev_snaps else ("MAJOR" if diff_result.defacement_detected else "MINOR"),
        ),
        active_scan=active_result,
        metrics=ScanMetrics(
            raw_metrics={"defacement_detected": diff_result.defacement_detected, "similarity_score": diff_result.similarity_score}
        )
    )

    # 8. Risk Engine
    assessment = risk_engine.assess(evidence)

    # 9. Explainable AI
    xai_output = explainability.explain(evidence, assessment)

    # 10. Attack Story
    story = attack_story.generate(assessment, xai_output)

    # 11. Build Incident
    incident = incident_builder.build_incident(evidence, assessment, xai_output, story, asset_id, uid)
    
    # ── Change Classification ──
    has_new_critical_high = any(f.severity.lower() in ("critical", "high") for f in assessment.findings)
    
    # Classify changes
    if diff_result.defacement_detected or pixel_diff_pct > 30.0 or has_new_critical_high:
        change_class = "Critical"
    elif diff_result.similarity_score >= 0.15 or pixel_diff_pct > 15.0:
        change_class = "Major"
    elif diff_result.similarity_score > 0.0 or pixel_diff_pct > 1.0:
        change_class = "Minor"
    else:
        change_class = "None"

    print(f"Classification: {change_class} (Similarity distance: {diff_result.similarity_score}, Pixel diff: {pixel_diff_pct:.2f}%)")

    # 12. Save to Firestore
    incident_dict = incident.model_dump(mode="json")
    incident_dict["uid"] = uid
    incident_dict["overall_grade"] = assessment.summary.overall_grade
    incident_dict["confidence_score"] = assessment.confidence.confidence_score
    incident_dict["verified_sources"] = incident_builder._build_verified_sources(assessment)
    incident_dict["critical_issues_count"] = assessment.statistics.critical_count
    incident_dict["change_classification"] = change_class
    incident_dict["similarity_score"] = diff_result.similarity_score
    incident_dict["pixel_diff_pct"] = pixel_diff_pct
    
    xai_by_title = {f.finding: f for f in xai_output.findings}
    findings_list = []
    for f in assessment.findings:
        x_f = xai_by_title.get(f.title)
        findings_list.append({
            "title": f.title,
            "severity": f.severity,
            "evidence_reference": f.evidence_reference,
            "owasp_mapping": x_f.owasp_mapping if x_f else ", ".join(f.owasp)
        })
    incident_dict["findings"] = findings_list
    incident_dict["top_recommendations"] = [f.recommendation for f in xai_output.findings if f.recommendation]
    
    if story.chains:
        incident_dict["attack_chain_analysis"] = {
            "chain_count": len(story.chains),
            "chain_titles": [c.chain_title for c in story.chains],
            "confidence": story.coverage.chain_confidence,
            "coverage_pct": story.coverage.evidence_coverage_percentage
        }
        
    # Save scan document
    incident_id = db.save_scan(incident_dict)
    
    # Save snapshot
    snap_dict = snapshot.to_firestore_dict(snap)
    snap_dict["owner_uid"] = uid
    snap_dict["asset_id"] = asset_id
    snap_dict["url"] = result.url
    snap_dict["timestamp"] = datetime.utcnow()
    db.save_snapshot(snap_dict)
    
    # Log Audit action
    db.log_action(uid, f"MONITOR_SCAN_COMPLETE", f"{url} [{change_class}]", result.resolved_ip)

    # ── Critical Alert Flow ──
    if pixel_diff_pct > 70.0:
        # Create alert doc in 'alerts' collection
        alert_title = f"Visual Defacement Alert: {result.hostname}"
        desc = (
            f"Severe page defacement detected during scheduled monitoring. "
            f"Visual Pixel Change: {pixel_diff_pct:.2f}% (exceeds 70% threshold)."
        )
        db_client = db.get_db()
        db_client.collection("alerts").add({
            "owner_uid": uid,
            "asset_id": asset_id,
            "incident_id": incident_id,
            "timestamp": datetime.utcnow(),
            "level": "Critical",
            "title": alert_title,
            "description": desc,
            "status": "UNREAD"
        })
        
        # Add a dashboard alert notification event to the incident timeline
        db.log_action(uid, "CRITICAL_ALERT", f"Defacement or Critical Threat on {url}")

    # ── Update Asset status ──
    db_client = db.get_db()
    # Get current monitoring interval from asset doc
    asset_ref = db_client.collection(db.ASSETS).document(asset_id)
    asset_doc = asset_ref.get()
    
    interval_mins = 1440  # Default 24 hours
    if asset_doc.exists:
        interval_mins = asset_doc.to_dict().get("monitoring_interval_minutes", 1440)
        
    next_run = datetime.utcnow() + timedelta(minutes=interval_mins)
    
    asset_ref.update({
        "last_scanned": datetime.utcnow(),
        "next_scheduled_scan_at": next_run,
        "defacement_detected": diff_result.defacement_detected or pixel_diff_pct > 30.0,
        "risk_score": assessment.summary.overall_security_score,
        "risk_level": assessment.summary.overall_severity,
        "vulns": len(assessment.findings),
        "health_status": "HEALTHY"
    })
    
    print(f"Scheduled scan finished successfully. Next scan scheduled at {next_run} UTC.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelAI SOC Headless Scanner CLI")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--uid", required=True, help="Firebase User UID")
    parser.add_argument("--asset_id", required=True, help="Monitored Asset Document ID")
    
    args = parser.parse_args()
    
    try:
        run_scan(args.url, args.uid, args.asset_id)
        sys.exit(0)
    except Exception as exc:
        print(f"Scheduled scan failed with exception: {exc}")
        sys.exit(1)

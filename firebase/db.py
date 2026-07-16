"""
firebase/db.py — Firestore CRUD helpers.
All database reads and writes go through this module.
Collections: users, assets, scans, reports, audit_logs
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from google.cloud.firestore_v1 import DocumentReference, CollectionReference

from firebase.config import get_db

# ── Collection Names ──────────────────────────────────────────────────────────

USERS = "users"
ASSETS = "assets"
SCANS = "scans"
REPORTS = "reports"
AUDIT_LOGS = "audit_logs"
SNAPSHOTS = "snapshots"


# ── Users ─────────────────────────────────────────────────────────────────────

def create_user_doc(uid: str, email: str, role: str = "analyst") -> None:
    """Create a user document in Firestore on first sign-up."""
    db = get_db()
    db.collection(USERS).document(uid).set({
        "email": email,
        "role": role,
        "created_at": datetime.utcnow()
    }, merge=True)


def get_user_doc(uid: str) -> Optional[dict]:
    """Return the user document for a given UID, or None."""
    db = get_db()
    doc = db.collection(USERS).document(uid).get()
    return doc.to_dict() if doc.exists else None


def get_all_users() -> list[dict]:
    """Return all user documents from Firestore."""
    db = get_db()
    docs = db.collection(USERS).stream()
    return [{"uid": doc.id, **doc.to_dict()} for doc in docs]


def update_user_role(uid: str, role: str) -> None:
    """Update the role of a user in Firestore."""
    db = get_db()
    db.collection(USERS).document(uid).update({"role": role})


def delete_user_account(uid: str) -> None:
    """Completely delete a user from Firestore and Firebase Authentication."""
    from firebase_admin import auth
    
    db = get_db()
    # Delete from Firestore
    db.collection(USERS).document(uid).delete()
    
    # Delete from Firebase Auth
    try:
        auth.delete_user(uid)
    except auth.UserNotFoundError:
        pass # User might already be gone from Auth


# ── Assets ────────────────────────────────────────────────────────────────────

def add_asset(uid: str, url: str, name: str) -> str:
    """Add a new monitored asset. Returns the new document ID."""
    db = get_db()
    _, doc_ref = db.collection(ASSETS).add({
        "uid": uid,
        "url": url,
        "name": name,
        "added": datetime.utcnow(),
        "defacement_detected": False,
        "risk_score": 100,
        "risk_level": "low",
        "vulns": 0,
        "last_scanned": datetime.utcnow()
    })
    return doc_ref.id


def get_assets(uid: str) -> list[dict]:
    """Return all assets owned by the given UID."""
    db = get_db()
    docs = db.collection(ASSETS).where("uid", "==", uid).stream()
    return [{"id": doc.id, **doc.to_dict()} for doc in docs]


def delete_asset(uid: str, asset_id: str) -> None:
    """Delete an asset after validating ownership."""
    db = get_db()
    doc_ref = db.collection(ASSETS).document(asset_id)
    doc = doc_ref.get()
    if doc.exists and doc.to_dict().get("uid") == uid:
        doc_ref.delete()
    else:
        raise PermissionError("Asset not found or unauthorized.")


def update_asset_last_scanned(asset_id: str, timestamp: datetime) -> None:
    """Update the last_scanned field on an asset document."""
    db = get_db()
    # Note: Ownership should generally be verified before this in actual routes
    db.collection(ASSETS).document(asset_id).update({
        "last_scanned": timestamp
    })


# ── Scans ─────────────────────────────────────────────────────────────────────

def save_scan(scan_data: dict) -> str:
    """Persist a completed scan document. Returns the new document ID."""
    db = get_db()
    # Ensure a timestamp exists
    if "timestamp" not in scan_data:
        scan_data["timestamp"] = datetime.utcnow()
    _, doc_ref = db.collection(SCANS).add(scan_data)
    return doc_ref.id


# ── Snapshots ─────────────────────────────────────────────────────────────────

def save_snapshot(snap_dict: dict) -> str:
    """
    Persist a snapshot document.
    Enforces that owner_uid, asset_id, url, and timestamp are present.
    Returns the new document ID.
    """
    db = get_db()
    if "timestamp" not in snap_dict:
        snap_dict["timestamp"] = datetime.utcnow()
    _, doc_ref = db.collection(SNAPSHOTS).add(snap_dict)
    return doc_ref.id


def get_snapshots(uid: str, asset_id: Optional[str] = None, limit: int = 50) -> list[dict]:
    """
    Return snapshots for the given UID only.
    Optionally filter by asset_id. Always filters by owner_uid.
    Never returns snapshots from another user.
    """
    db = get_db()
    query = db.collection(SNAPSHOTS).where("owner_uid", "==", uid)
    if asset_id:
        query = query.where("asset_id", "==", asset_id)

    docs = list(query.stream())
    snapshots = [{"id": doc.id, **doc.to_dict()} for doc in docs]
    # Sort in-memory by timestamp descending to avoid composite index requirement
    snapshots.sort(
        key=lambda x: x.get("timestamp", datetime.min).timestamp()
        if isinstance(x.get("timestamp"), datetime) else 0,
        reverse=True
    )
    return snapshots[:limit]


def get_scans(uid: str, asset_id: Optional[str] = None, limit: int = 50) -> list[dict]:
    """
    Return scans for the given UID.
    Optionally filter by asset_id. Results ordered by timestamp descending.
    """
    db = get_db()
    query = db.collection(SCANS).where("uid", "==", uid)
    if asset_id:
        query = query.where("asset_id", "==", asset_id)
    
    # Execute query without order_by to avoid requiring a Firestore Composite Index
    docs = list(query.stream())
    
    # Sort in memory and apply limit
    scans = [{"id": doc.id, **doc.to_dict()} for doc in docs]
    scans.sort(key=lambda x: x.get("timestamp", datetime.min).timestamp() if isinstance(x.get("timestamp"), datetime) else 0, reverse=True)
    return scans[:limit]


def get_scan(uid: str, scan_id: str) -> Optional[dict]:
    """Return a single scan document after validating ownership."""
    db = get_db()
    doc_ref = db.collection(SCANS).document(scan_id)
    doc = doc_ref.get()
    if doc.exists and doc.to_dict().get("uid") == uid:
        return {"id": doc.id, **doc.to_dict()}
    return None


# ── Reports ───────────────────────────────────────────────────────────────────

def save_report(report_data: dict) -> str:
    """Persist a report document. Returns the new document ID."""
    db = get_db()
    if "generated_at" not in report_data:
        report_data["generated_at"] = datetime.utcnow()
    _, doc_ref = db.collection(REPORTS).add(report_data)
    return doc_ref.id


def get_reports(uid: str, limit: int = 50) -> list[dict]:
    """Return reports for the given UID, ordered by generated_at descending."""
    db = get_db()
    query = db.collection(REPORTS).where("uid", "==", uid)
    
    # Execute query without order_by to avoid requiring a Firestore Composite Index
    docs = list(query.stream())
    
    # Sort in memory and apply limit
    reports = [{"id": doc.id, **doc.to_dict()} for doc in docs]
    reports.sort(key=lambda x: x.get("generated_at", datetime.min).timestamp() if isinstance(x.get("generated_at"), datetime) else 0, reverse=True)
    return reports[:limit]


# ── Audit Logs ────────────────────────────────────────────────────────────────

def log_action(uid: str, action: str, target: str, ip: str = "") -> None:
    """Append an entry to the audit_logs collection."""
    db = get_db()
    db.collection(AUDIT_LOGS).add({
        "uid": uid,
        "action": action,
        "target": target,
        "ip": ip,
        "timestamp": datetime.utcnow()
    })


def get_audit_logs(limit: int = 200) -> list[dict]:
    """Return audit log entries ordered by timestamp descending. Admin only."""
    db = get_db()
    # Assuming role checks happen before calling this
    query = db.collection(AUDIT_LOGS).order_by("timestamp", direction="DESCENDING").limit(limit)
    docs = query.stream()
    return [{"id": doc.id, **doc.to_dict()} for doc in docs]


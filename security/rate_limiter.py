"""
security/rate_limiter.py — Per-user scan rate limiting.

Prevents scan abuse by enforcing a maximum number of scans per user
within a rolling time window. State is stored in Firestore audit_logs
(no additional collection required).

This is a best-effort, server-side limiter. It is not a substitute
for Firebase Security Rules.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional


# ── Limits ────────────────────────────────────────────────────────────────────

MAX_SCANS_PER_WINDOW = 10          # maximum scans allowed per user
WINDOW_SECONDS = 3600              # rolling window duration (1 hour)


# ── Public Interface ──────────────────────────────────────────────────────────

def check_rate_limit(uid: str) -> None:
    """
    Check whether the given user has exceeded the scan rate limit.

    Counts scan actions in audit_logs within the last WINDOW_SECONDS.
    Raises RateLimitError if the limit is exceeded.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(seconds=WINDOW_SECONDS)
    
    count = get_scan_count(uid, since)
    if count >= MAX_SCANS_PER_WINDOW:
        retry_seconds = seconds_until_reset(uid)
        raise RateLimitError(uid, retry_seconds)


def get_scan_count(uid: str, since: datetime) -> int:
    """
    Return the number of scan actions performed by uid since the given datetime.
    Reads from the audit_logs Firestore collection.
    """
    from firebase.config import get_db
    db = get_db()
    
    # In Firestore, we query where action is 'scan' and timestamp >= since
    query = (
        db.collection("audit_logs")
        .where("uid", "==", uid)
        .where("action", "==", "scan")
        .where("timestamp", ">=", since)
    )
    # Using count() aggregation available in newer firestore SDKs is better, 
    # but stream() len is safe for small numbers like MAX_SCANS_PER_WINDOW=10.
    docs = list(query.stream())
    return len(docs)


def seconds_until_reset(uid: str) -> int:
    """
    Return the number of seconds until the user's oldest scan in the window expires.
    Returns 0 if the user is not rate-limited.
    """
    from firebase.config import get_db
    db = get_db()
    
    now = datetime.now(timezone.utc)
    since = now - timedelta(seconds=WINDOW_SECONDS)
    
    query = (
        db.collection("audit_logs")
        .where("uid", "==", uid)
        .where("action", "==", "scan")
        .where("timestamp", ">=", since)
        .order_by("timestamp", direction="ASCENDING")
        .limit(1)
    )
    
    docs = list(query.stream())
    if not docs:
        return 0
        
    oldest_scan_time = docs[0].to_dict().get("timestamp")
    if not oldest_scan_time:
        return 0
        
    # Ensure it's timezone-aware
    if oldest_scan_time.tzinfo is None:
        oldest_scan_time = oldest_scan_time.replace(tzinfo=timezone.utc)
        
    reset_time = oldest_scan_time + timedelta(seconds=WINDOW_SECONDS)
    delta = reset_time - now
    
    return max(0, int(delta.total_seconds()))


# ── Custom Exception ──────────────────────────────────────────────────────────

class RateLimitError(Exception):
    """Raised when a user exceeds the scan rate limit."""

    def __init__(self, uid: str, retry_after_seconds: int) -> None:
        self.uid = uid
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Rate limit exceeded. Try again in {retry_after_seconds} seconds."
        )

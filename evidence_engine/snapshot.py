"""
evidence_engine/snapshot.py — HTML snapshot capture and storage.

Captures a deterministic text snapshot of a webpage for baseline
comparison. Snapshots are stored in Firestore as part of the scan record.

IMPORTANT: Raw HTML is NEVER stored in Firestore or passed to the AI layer.
Only the normalised text_content is used for comparison.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from evidence_engine.fetcher import FetchResult


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class Snapshot:
    """
    A point-in-time snapshot of a website's visible content.
    Stored in Firestore as part of the asset document.
    """
    url: str
    captured_at: datetime
    text_fingerprint: str          # SHA-256 hex digest of text_content
    dom_fingerprint: str           # SHA-256 hex digest of structural DOM
    text_content: str              # visible text only — no HTML, no scripts
    word_count: int
    status_code: int
    screenshot_path: str = ""      # Path to local PNG file
    html_path: str = ""            # Path to local HTML file


# ── Public Interface ──────────────────────────────────────────────────────────

def capture(fetch_result: FetchResult) -> Snapshot:
    """
    Create a Snapshot from a FetchResult.
    Calls out to Playwright to capture actual screenshots and DOM hashes.
    Strips all HTML tags, scripts, styles, and invisible markup from the
    raw HTML. Only the normalised visible text is retained and hashed.
    """
    from evidence_engine.browser import capture_page
    
    # 1. Capture actual evidence using browser
    browser_data = capture_page(fetch_result.url)
    
    # 2. Extract text from the dynamic DOM (instead of static fetch_result if preferred, 
    # but for consistency we use browser's rendered HTML)
    text = _extract_visible_text(browser_data["raw_html"])
    fp = fingerprint(text)

    return Snapshot(
        url=fetch_result.url,
        captured_at=datetime.now(timezone.utc),
        text_fingerprint=fp,
        dom_fingerprint=browser_data["dom_fingerprint"],
        text_content=text,
        word_count=len(text.split()),
        status_code=fetch_result.status_code,
        screenshot_path=browser_data["screenshot_path"],
        html_path=browser_data["html_path"]
    )


def fingerprint(text_content: str) -> str:
    """
    Compute a SHA-256 fingerprint of the text content.
    Used to detect changes without storing raw HTML.
    """
    return hashlib.sha256(text_content.encode("utf-8", errors="replace")).hexdigest()


def to_firestore_dict(snapshot: Snapshot) -> dict:
    """Serialise a Snapshot to a Firestore-compatible dict."""
    return {
        "url":              snapshot.url,
        "captured_at":      snapshot.captured_at,
        "text_fingerprint": snapshot.text_fingerprint,
        "dom_fingerprint":  snapshot.dom_fingerprint,
        "screenshot_path":  snapshot.screenshot_path,
        "html_path":        snapshot.html_path,
        # Store a truncated version to stay within Firestore 1 MB doc limits.
        # The full text is only needed locally for diff computation.
        "text_content":     snapshot.text_content[:50_000],
        "word_count":       snapshot.word_count,
        "status_code":      snapshot.status_code,
    }


def from_firestore_dict(data: dict) -> Snapshot:
    """Deserialise a Snapshot from a Firestore document dict."""
    captured_at = data.get("captured_at")
    # Firestore returns timestamps as datetime objects; handle both
    if not isinstance(captured_at, datetime):
        captured_at = datetime.now(timezone.utc)

    return Snapshot(
        url=data.get("url", ""),
        captured_at=captured_at,
        text_fingerprint=data.get("text_fingerprint", ""),
        dom_fingerprint=data.get("dom_fingerprint", ""),
        text_content=data.get("text_content", ""),
        word_count=data.get("word_count", 0),
        status_code=data.get("status_code", 0),
        screenshot_path=data.get("screenshot_path", ""),
        html_path=data.get("html_path", "")
    )


# ── Private Helpers ───────────────────────────────────────────────────────────

# Patterns to strip entirely (scripts, styles, comments)
_STRIP_TAGS = re.compile(
    r"<(script|style|noscript|head|meta|link|svg|iframe)[^>]*>.*?</\1>",
    re.DOTALL | re.IGNORECASE,
)
_HTML_COMMENTS = re.compile(r"<!--.*?-->", re.DOTALL)
_ALL_TAGS = re.compile(r"<[^>]+>")
_WHITESPACE = re.compile(r"\s+")


def _extract_visible_text(html: str) -> str:
    """
    Extract only the visible text from raw HTML.

    Steps:
      1. Remove <script>, <style>, <head>, <svg>, <iframe> blocks in full.
      2. Remove HTML comments.
      3. Strip all remaining HTML tags.
      4. Collapse whitespace and strip leading/trailing space.

    Returns plain, normalised text — safe to store, compare, and hash.
    """
    # Step 1: Remove script/style blocks completely
    text = _STRIP_TAGS.sub(" ", html)

    # Step 2: Remove HTML comments
    text = _HTML_COMMENTS.sub(" ", text)

    # Step 3: Strip remaining tags
    text = _ALL_TAGS.sub(" ", text)

    # Step 4: Collapse whitespace
    text = _WHITESPACE.sub(" ", text).strip()

    return text

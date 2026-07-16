"""
services/scanner.py — Compatibility shim.

DEPRECATED: This module is superseded by the Evidence Engine architecture.
It is kept to avoid breaking existing imports during transition.

New code should import directly from:
  evidence_engine.fetcher   — website fetching
  evidence_engine.snapshot  — snapshot capture
  evidence_engine.diff      — defacement detection

The Evidence Engine pipeline is:
  security/  →  evidence_engine/  →  ai/
"""

from __future__ import annotations

# Re-export Evidence Engine types so existing imports continue to work
from evidence_engine.fetcher import FetchResult as SnapshotResult
from evidence_engine.diff import DiffResult as DefacementResult
from evidence_engine.fetcher import fetch as fetch_snapshot
from evidence_engine.diff import compare as compare_snapshots
from evidence_engine.snapshot import _extract_visible_text as extract_text
from evidence_engine.diff import compute_similarity

__all__ = [
    "SnapshotResult",
    "DefacementResult",
    "fetch_snapshot",
    "compare_snapshots",
    "extract_text",
    "compute_similarity",
]

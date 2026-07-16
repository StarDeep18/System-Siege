"""
evidence_engine/diff.py — Deterministic snapshot comparison and diff generation.

Compares a current snapshot against a saved baseline to detect defacement.
Produces structured, quantitative diff evidence.

All logic is deterministic. No AI involvement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher

from evidence_engine.snapshot import Snapshot


# ── Thresholds ────────────────────────────────────────────────────────────────

DEFACEMENT_THRESHOLD = 0.30        # similarity distance above this = defacement detected


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class DiffResult:
    """
    Quantitative diff evidence between baseline and current snapshot.
    Passed to the Evidence Engine output — never to the AI directly.
    """
    baseline_fingerprint: str
    current_fingerprint: str
    fingerprints_match: bool
    dom_fingerprints_match: bool
    similarity_score: float          # 0.0 = identical, 1.0 = completely different
    defacement_detected: bool
    word_count_delta: int            # current - baseline (negative means content removed)
    changed_segments: list[str] = field(default_factory=list)  # sample of changed text


# ── Public Interface ──────────────────────────────────────────────────────────

def compare(baseline: Snapshot, current: Snapshot) -> DiffResult:
    """
    Compare two snapshots and return a DiffResult.
    Sets defacement_detected = True if similarity_score >= DEFACEMENT_THRESHOLD.

    Similarity score:
        0.0  = content is identical
        1.0  = content is completely different
    """
    fingerprints_match = baseline.text_fingerprint == current.text_fingerprint
    dom_match = getattr(baseline, "dom_fingerprint", "") == getattr(current, "dom_fingerprint", "")

    if fingerprints_match and dom_match:
        # Fingerprints match — no need to do full text comparison
        return DiffResult(
            baseline_fingerprint=baseline.text_fingerprint,
            current_fingerprint=current.text_fingerprint,
            fingerprints_match=True,
            dom_fingerprints_match=True,
            similarity_score=0.0,
            defacement_detected=False,
            word_count_delta=current.word_count - baseline.word_count,
            changed_segments=[],
        )

    # Fingerprints differ — compute full similarity distance
    score = compute_similarity(baseline.text_content, current.text_content)
    # Also trigger defacement if DOM structural hash changed radically 
    # (though typically we just rely on the text similarity for the flag, but we'll include it)
    defacement = score >= DEFACEMENT_THRESHOLD or not dom_match
    segments = extract_changed_segments(baseline.text_content, current.text_content)

    return DiffResult(
        baseline_fingerprint=baseline.text_fingerprint,
        current_fingerprint=current.text_fingerprint,
        fingerprints_match=fingerprints_match,
        dom_fingerprints_match=dom_match,
        similarity_score=round(score, 4),
        defacement_detected=defacement,
        word_count_delta=current.word_count - baseline.word_count,
        changed_segments=segments,
    )


def compute_similarity(text_a: str, text_b: str) -> float:
    """
    Compute a normalised similarity distance between two text strings.

    Returns 0.0 for identical texts, 1.0 for completely different texts.
    Uses difflib.SequenceMatcher (ratio gives similarity; we invert to get distance).

    SequenceMatcher.ratio() returns:
        1.0 = identical
        0.0 = completely different

    We invert: distance = 1.0 - ratio
    """
    if not text_a and not text_b:
        return 0.0
    if not text_a or not text_b:
        return 1.0

    # Use the autojunk heuristic for speed on large texts
    ratio = SequenceMatcher(None, text_a, text_b, autojunk=True).ratio()
    return round(1.0 - ratio, 4)


def extract_changed_segments(text_a: str, text_b: str, max_segments: int = 5) -> list[str]:
    """
    Return a sample of text segments that differ between the two texts.
    Limited to max_segments to avoid large payloads.

    Uses SequenceMatcher.get_matching_blocks() to identify non-matching regions.
    Each segment is a short excerpt from the current (b) text at a changed position.
    """
    if not text_a or not text_b:
        return []

    matcher = SequenceMatcher(None, text_a, text_b, autojunk=True)
    segments: list[str] = []

    # get_opcodes returns a list of tagged range tuples
    # Tags: 'replace', 'delete', 'insert', 'equal'
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "insert"):
            # Extract the changed portion from the *current* text
            excerpt = text_b[j1:j2].strip()
            if excerpt:
                # Truncate long excerpts for readability
                if len(excerpt) > 200:
                    excerpt = excerpt[:200] + "…"
                segments.append(excerpt)

        if len(segments) >= max_segments:
            break

    return segments

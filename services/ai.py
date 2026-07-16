"""
services/ai.py — Compatibility shim.

DEPRECATED: This module is superseded by the AI Incident Intelligence architecture.
It is kept to avoid breaking existing imports during transition.

New code should import directly from:
  ai.explainability     — XAI findings and executive summary
  ai.attack_story       — hypothetical attack narrative
  ai.report_generator   — executive report generation

ARCHITECTURE INVARIANT:
  The AI layer receives ONLY structured EvidenceReport objects.
  It must NEVER receive raw HTML, JavaScript, CSS, or webpage content.

The full pipeline is:
  security/  →  evidence_engine/  →  ai/
"""

from __future__ import annotations

# Re-export AI layer types so existing imports continue to work
from ai.explainability import XAIFinding, XAIOutput, explain as analyse
from ai.attack_story import AttackStory, generate as generate_attack_story
from ai.report_generator import ExecutiveReport

__all__ = [
    "XAIFinding",
    "XAIOutput",
    "AttackStory",
    "ExecutiveReport",
    "analyse",
    "generate_attack_story",
]

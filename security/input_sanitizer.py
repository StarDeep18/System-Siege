"""
security/input_sanitizer.py — Input sanitisation for all user-supplied strings.

Sanitises strings before they are stored, displayed, or used in any
downstream operation. This module never validates URLs — that belongs
to url_validator.py.
"""

from __future__ import annotations

import html
import re
import unicodedata


# ── Limits ────────────────────────────────────────────────────────────────────

MAX_ASSET_NAME_LENGTH = 128
MAX_GENERAL_STRING_LENGTH = 256
MAX_NOTES_LENGTH = 1024


# ── Public Interface ──────────────────────────────────────────────────────────

def sanitise_asset_name(name: str) -> str:
    """
    Sanitise a user-supplied asset display name.
    - Strips leading/trailing whitespace
    - Normalises unicode (NFC)
    - Removes control characters
    - Enforces MAX_ASSET_NAME_LENGTH
    Raises ValueError if the result is empty or too long.
    """
    if not name:
        raise ValueError("Asset name cannot be empty.")
    
    clean_name = name.strip()
    clean_name = normalise_unicode(clean_name)
    clean_name = strip_control_characters(clean_name)
    
    if not clean_name:
        raise ValueError("Asset name cannot be empty after sanitisation.")
        
    if len(clean_name) > MAX_ASSET_NAME_LENGTH:
        raise ValueError(f"Asset name exceeds maximum length of {MAX_ASSET_NAME_LENGTH} characters.")
        
    return clean_name


def sanitise_string(value: str, max_length: int = MAX_GENERAL_STRING_LENGTH) -> str:
    """
    General-purpose string sanitisation.
    - Strips whitespace
    - Removes control characters
    - Enforces max_length
    Raises ValueError if the result is empty.
    """
    if not value:
        raise ValueError("String cannot be empty.")
        
    clean_val = value.strip()
    clean_val = strip_control_characters(clean_val)
    
    if not clean_val:
        raise ValueError("String cannot be empty after sanitisation.")
        
    if len(clean_val) > max_length:
        raise ValueError(f"String exceeds maximum length of {max_length} characters.")
        
    return clean_val


def escape_for_display(value: str) -> str:
    """
    HTML-escape a string before rendering it in a Streamlit markdown block.
    Use for any data that may originate from external sources.
    """
    return html.escape(str(value))


def strip_control_characters(value: str) -> str:
    """Remove non-printable and control characters from a string."""
    # Matches any control character (unicode categories Cc, Cf)
    return "".join(ch for ch in value if unicodedata.category(ch)[0] != 'C')


def normalise_unicode(value: str) -> str:
    """Normalise a string to NFC unicode form to prevent homograph attacks."""
    return unicodedata.normalize("NFC", value)


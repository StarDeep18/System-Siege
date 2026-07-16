"""
firebase/auth.py — Firebase Authentication helpers.
Wraps REST API calls for sign-in and sign-up, and Admin SDK for token verification.
"""

from __future__ import annotations

import os
from typing import Optional

import requests
from firebase_admin import auth

from firebase.config import get_web_config

# ── Constants ─────────────────────────────────────────────────────────────────

_SIGN_IN_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
_SIGN_UP_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signUp"


# ── Public Interface ──────────────────────────────────────────────────────────

def sign_in(email: str, password: str) -> dict:
    """
    Sign in with email and password via Firebase REST API.
    Returns the Firebase response dict on success.
    Raises ValueError with a user-safe message on failure.
    """
    config = get_web_config()
    api_key = config.get("apiKey")
    if not api_key:
        raise ValueError("Firebase API Key is missing. Check your configuration.")

    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    
    resp = requests.post(f"{_SIGN_IN_URL}?key={api_key}", json=payload)
    if resp.status_code == 200:
        return resp.json()
        
    error_msg = resp.json().get("error", {}).get("message", "Authentication failed.")
    raise ValueError(f"Sign-in failed: {error_msg}")


def sign_up(email: str, password: str) -> dict:
    """
    Register a new user via Firebase REST API.
    Returns the Firebase response dict on success.
    Raises ValueError with a user-safe message on failure.
    """
    config = get_web_config()
    api_key = config.get("apiKey")
    if not api_key:
        raise ValueError("Firebase API Key is missing.")

    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    
    resp = requests.post(f"{_SIGN_UP_URL}?key={api_key}", json=payload)
    if resp.status_code == 200:
        return resp.json()
        
    error_msg = resp.json().get("error", {}).get("message", "Registration failed.")
    raise ValueError(f"Sign-up failed: {error_msg}")


def verify_id_token(id_token: str) -> dict:
    """
    Verify a Firebase ID token using the Admin SDK.
    Returns the decoded token claims dict.
    Raises ValueError if the token is invalid or expired.
    """
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        raise ValueError(f"Invalid or expired session token: {str(e)}")


def get_user_role(uid: str) -> str:
    """
    Retrieve the role for a given UID from Firestore users collection.
    Returns 'analyst' as the default role if none is set.
    """
    try:
        from firebase.config import get_db
        db = get_db()
        user_doc = db.collection("users").document(uid).get()
        if user_doc.exists:
            return user_doc.to_dict().get("role", "analyst")
    except Exception:
        pass
    return "analyst"


def sign_out() -> None:
    """
    Clear the authenticated user from Streamlit session state.
    """
    import streamlit as st
    st.session_state.pop("id_token", None)
    st.session_state.pop("uid", None)
    st.session_state.pop("user_email", None)
    st.session_state.pop("role", None)
    # Don't pop 'active_page' to let them remain on the login/dashboard screen, or pop to reset
    st.session_state["user"] = None

"""
firebase/config.py — Firebase SDK initialisation.
Reads credentials from environment variables and initialises the Admin SDK.
Called once at app startup from app.py.
"""

import json
import os

import firebase_admin
from firebase_admin import credentials, firestore, auth

# ── Internal state ────────────────────────────────────────────────────────────

_app: firebase_admin.App | None = None
_db: firestore.Client | None = None


def initialise() -> None:
    """
    Initialise the Firebase Admin SDK from environment variables.
    Safe to call multiple times — subsequent calls are no-ops.
    """
    global _app, _db

    if _db is not None:
        return

    service_account_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()

    if not service_account_json:
        raise EnvironmentError(
            "FIREBASE_SERVICE_ACCOUNT_JSON is not set. "
            "Copy .env.example to .env and fill in your credentials."
        )

    # Support both a direct file path or a raw JSON string
    if service_account_json.endswith(".json"):
        if not os.path.exists(service_account_json):
            raise EnvironmentError(
                f"Firebase credentials file not found: '{service_account_json}'\n"
                "Please make sure the file exists in the correct folder."
            )
        cred = credentials.Certificate(service_account_json)
    else:
        try:
            service_account_dict = json.loads(service_account_json)
        except json.JSONDecodeError:
            raise EnvironmentError(
                "FIREBASE_SERVICE_ACCOUNT_JSON is neither a valid .json file path nor a valid JSON string."
            )
        cred = credentials.Certificate(service_account_dict)
    
    # Handle Streamlit hot-reloading where the app might already exist
    try:
        _app = firebase_admin.get_app()
    except ValueError:
        _app = firebase_admin.initialize_app(cred)
        
    _db = firestore.client()


def get_db() -> firestore.Client:
    """Return the Firestore client. Raises if not initialised."""
    if _db is None:
        raise RuntimeError("Firebase has not been initialised. Call initialise() first.")
    return _db


def get_project_id() -> str:
    """Return the Firebase project ID from environment."""
    return os.environ.get("FIREBASE_PROJECT_ID", "")


def get_web_config() -> dict:
    """
    Return the client-side Firebase web configuration dict.
    Used for Firebase REST Auth calls (sign-in / sign-up).
    """
    return {
        "apiKey": os.environ.get("FIREBASE_API_KEY", ""),
        "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN", ""),
        "projectId": os.environ.get("FIREBASE_PROJECT_ID", ""),
        "storageBucket": os.environ.get("FIREBASE_STORAGE_BUCKET", ""),
        "messagingSenderId": os.environ.get("FIREBASE_MESSAGING_SENDER_ID", ""),
        "appId": os.environ.get("FIREBASE_APP_ID", ""),
    }

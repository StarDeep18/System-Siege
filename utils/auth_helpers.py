"""
utils/auth_helpers.py — Reusable helpers for authentication and registration hardening.
"""

from __future__ import annotations

import re


def validate_email_domain(email: str) -> tuple[bool, str]:
    """
    Validate email address format and reject obviously fake domains.
    Returns (is_valid, error_message).
    """
    if not email or "@" not in email:
        return False, "Invalid email address format."
    
    domain = email.split("@")[-1].lower()
    
    # Reject common fake domains
    invalid_domains = ["example.com", "test.com", "localhost", "invalid"]
    if domain in invalid_domains or domain.endswith(".invalid"):
        return False, f"Registration with domain '@{domain}' is not allowed. Please use a real email."
        
    return True, ""


def password_strength(password: str) -> tuple[str, dict[str, bool]]:
    """
    Evaluate password strength and return a checklist of satisfied requirements.
    Requirements:
    - 12 Characters
    - Uppercase letter
    - Lowercase letter
    - Number
    - Special Character
    
    Returns (Strength Level, Checklist dict)
    """
    if not password:
        password = ""
        
    checklist = {
        "12 Characters": len(password) >= 12,
        "Uppercase": bool(re.search(r'[A-Z]', password)),
        "Lowercase": bool(re.search(r'[a-z]', password)),
        "Number": bool(re.search(r'[0-9]', password)),
        "Special Character": bool(re.search(r'[^A-Za-z0-9]', password))
    }
    
    score = sum(checklist.values())
    
    if score <= 2:
        strength = "Weak"
    elif score == 3:
        strength = "Fair"
    elif score == 4:
        strength = "Good"
    else:
        strength = "Strong"
        
    return strength, checklist


def validate_password(password: str) -> tuple[bool, str]:
    """
    Enforce strict password requirements before registration.
    Returns (is_valid, error_message).
    """
    strength, checklist = password_strength(password)
    
    if not checklist["12 Characters"]:
        return False, "Password must be at least 12 characters long."
    if not checklist["Uppercase"]:
        return False, "Password must contain at least one uppercase letter."
    if not checklist["Lowercase"]:
        return False, "Password must contain at least one lowercase letter."
    if not checklist["Number"]:
        return False, "Password must contain at least one digit."
    if not checklist["Special Character"]:
        return False, "Password must contain at least one special character."
        
    return True, ""


def map_firebase_error(raw_error: str) -> str:
    """
    Translate raw Firebase error constants into user-friendly messages.
    """
    error_mapping = {
        "EMAIL_EXISTS": "This email is already registered.",
        "INVALID_PASSWORD": "Incorrect email or password.",
        "INVALID_LOGIN_CREDENTIALS": "Incorrect email or password.",
        "USER_NOT_FOUND": "No account exists with this email.",
        "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many failed login attempts. Please wait a few minutes before trying again.",
        "USER_DISABLED": "This account has been disabled by an administrator.",
        "OPERATION_NOT_ALLOWED": "Email/password authentication is not enabled on the server.",
        "INVALID_EMAIL": "The email address is improperly formatted."
    }
    
    # Extract the core error string if it's buried in a longer message
    for key, user_msg in error_mapping.items():
        if key in raw_error:
            return user_msg
            
    # Fallback to a generic error if it's unmapped to avoid exposing raw details
    return "Authentication failed. Please check your credentials and try again."

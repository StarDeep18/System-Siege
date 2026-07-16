"""
security/ownership.py — Resource ownership and role-based access enforcement.

Centralises all ownership and role checks in one place so they cannot
be accidentally bypassed. Called before any read or write on a
user-owned Firestore document.
"""

from __future__ import annotations


# ── Role Hierarchy ────────────────────────────────────────────────────────────

ROLE_HIERARCHY = {
    "admin": 2,
    "analyst": 1,
}


# ── Public Interface ──────────────────────────────────────────────────────────

def assert_owner(resource_uid: str, current_uid: str) -> None:
    """
    Assert that current_uid owns the resource identified by resource_uid.

    Raises PermissionError with a user-safe message if the check fails.
    Use before any read or write on a user-owned Firestore document.
    """
    if not resource_uid or not current_uid:
        raise PermissionError("Access denied: Invalid authentication context.")
        
    if resource_uid != current_uid:
        raise PermissionError("Access denied: You do not have permission to access this resource.")


def require_role(current_role: str, required_role: str) -> None:
    """
    Assert that current_role meets or exceeds required_role.

    Role hierarchy: admin > analyst.
    Raises PermissionError with a user-safe message if the check fails.
    """
    current_level = get_role_level(current_role)
    required_level = get_role_level(required_role)
    
    if current_level < required_level:
        raise PermissionError(f"Access denied: Requires '{required_role}' privileges.")


def is_admin(role: str) -> bool:
    """Return True if the given role is 'admin'."""
    return role == "admin"


def get_role_level(role: str) -> int:
    """Return the numeric level of a role. Unknown roles return 0."""
    return ROLE_HIERARCHY.get(role, 0)

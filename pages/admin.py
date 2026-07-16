"""
pages/admin.py — Admin Panel
Allows administrators to manage users and assign roles.
"""

from __future__ import annotations

import streamlit as st

from firebase import db


def render() -> None:
    """Render the Admin Panel page."""

    # ── Security Check ────────────────────────────────────────────────────────
    if st.session_state.get("role") != "admin":
        st.error("Access Denied: You do not have administrator privileges.")
        return

    # ── Page Header ───────────────────────────────────────────────────────────
    st.markdown(
        """
        <div style="margin-bottom: 2rem;">
            <div style="font-size: 0.8rem; color: #64748b; font-weight: 500;
                        text-transform: uppercase; letter-spacing: 0.05em;
                        font-family: 'Inter', sans-serif; margin-bottom: 0.25rem;">
                Control Center
            </div>
            <h1 style="margin: 0; font-family: 'Inter', sans-serif;
                       font-weight: 600; font-size: 1.8rem; color: #f8fafc;">
                Admin Panel
            </h1>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── User Management ───────────────────────────────────────────────────────
    st.markdown("### User Directory")
    st.write("Manage registered accounts and their access roles.")

    try:
        users = db.get_all_users()
    except Exception as exc:
        st.error(f"Failed to fetch users from Firestore: {exc}")
        return

    if not users:
        st.info("No users found in the system.")
        return

    # Display users
    for user in users:
        uid = user.get("uid")
        email = user.get("email", "Unknown Email")
        current_role = user.get("role", "analyst")
        created_at = user.get("created_at")
        
        ts_display = "Unknown"
        if created_at:
            # Handle possible datetime or string
            if hasattr(created_at, "strftime"):
                ts_display = created_at.strftime("%Y-%m-%d %H:%M UTC")
            else:
                ts_display = str(created_at)[:16]

        with st.container():
            st.markdown(
                f"""
                <div style="background-color: #1e293b; padding: 1rem;
                            border-radius: 8px; border: 1px solid #334155;
                            margin-bottom: 0.5rem; display: flex; align-items: center; justify-content: space-between;">
                    <div>
                        <div style="font-weight: 600; color: #f1f5f9; font-size: 1rem;">{email}</div>
                        <div style="color: #94a3b8; font-size: 0.8rem;">Joined: {ts_display} | UID: {uid}</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            
            # Use columns to position the role selector next to the user info
            col1, col2, col3 = st.columns([0.6, 0.3, 0.1])
            with col2:
                new_role = st.selectbox(
                    "Assign Role",
                    options=["analyst", "engineer", "admin"],
                    index=["analyst", "engineer", "admin"].index(current_role) if current_role in ["analyst", "engineer", "admin"] else 0,
                    key=f"role_{uid}",
                    label_visibility="collapsed"
                )
                
                if new_role != current_role:
                    # Immediately update role when selected
                    with st.spinner("Updating role..."):
                        try:
                            db.update_user_role(uid, new_role)
                            # If they updated their own role, update session state too
                            if uid == st.session_state.get("uid"):
                                st.session_state["role"] = new_role
                            
                            # Log the action
                            admin_uid = st.session_state.get("uid", "Unknown Admin")
                            db.log_action(admin_uid, "ROLE_UPDATE", f"Assigned role '{new_role}' to {email}")
                            
                            st.success(f"Role updated to {new_role}!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Failed to update role: {e}")
            with col3:
                if st.button("🗑️", key=f"delete_{uid}", help="Permanently delete user"):
                    if uid == st.session_state.get("uid"):
                        st.error("You cannot delete your own admin account.")
                    else:
                        with st.spinner("Deleting user..."):
                            try:
                                db.delete_user_account(uid)
                                admin_uid = st.session_state.get("uid", "Unknown Admin")
                                db.log_action(admin_uid, "DELETE_USER", f"Deleted account {email}")
                                st.success("User deleted successfully!")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed to delete user: {e}")
            
            st.markdown("<br>", unsafe_allow_html=True)

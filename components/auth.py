"""
components/auth.py — Login and registration UI.
Rendered by app.py when the user is not authenticated.
"""

from __future__ import annotations

import streamlit as st

from firebase import auth as firebase_auth
from firebase import db as firebase_db
from utils import security


# ── Public Interface ──────────────────────────────────────────────────────────

def render() -> None:
    """Render the login / register form."""
    st.markdown(
        """
        <div style="text-align: center; margin-bottom: 2rem;">
            <h1 style="font-family: 'Inter', sans-serif; font-weight: 600; color: #f8fafc; margin-bottom: 0.5rem;">
                SentinelAI SOC
            </h1>
            <p style="color: #94a3b8; font-family: 'Inter', sans-serif;">
                Sign in or create an account to access the dashboard.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    _, center_col, _ = st.columns([1, 1.5, 1])
    with center_col:
        tab1, tab2 = st.tabs(["Sign In", "Register"])
        
        with tab1:
            _render_login_tab()
            
        with tab2:
            _render_register_tab()


# ── Private Helpers ───────────────────────────────────────────────────────────

def _render_login_tab() -> None:
    """Render the sign-in form tab."""
    with st.form(key="login_form"):
        email = st.text_input("Email Address", placeholder="name@company.com")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Sign In", use_container_width=True)
        
        if submit:
            if not email or not password:
                st.error("Please enter both email and password.")
            else:
                _handle_login(email, password)


def _render_register_tab() -> None:
    """Render the registration form tab."""
    with st.form(key="register_form"):
        email = st.text_input("Email Address", placeholder="name@company.com")
        password = st.text_input("Password", type="password", help="Must be at least 6 characters.")
        password_confirm = st.text_input("Confirm Password", type="password")
        submit = st.form_submit_button("Create Account", use_container_width=True)
        
        if submit:
            if not email or not password:
                st.error("Please fill in all fields.")
            elif password != password_confirm:
                st.error("Passwords do not match.")
            elif len(password) < 6:
                st.error("Password must be at least 6 characters long.")
            else:
                _handle_register(email, password)


def _handle_login(email: str, password: str) -> None:
    """Attempt sign-in and update session state on success."""
    try:
        with st.spinner("Authenticating..."):
            response = firebase_auth.sign_in(email, password)
            
            uid = response.get("localId")
            if not uid:
                st.error("Authentication failed: No UID returned.")
                return
                
            # Fetch user role and additional data from Firestore
            user_doc = firebase_db.get_user_doc(uid)
            role = user_doc.get("role", "analyst") if user_doc else "analyst"
            display_name = email.split('@')[0]
            
            # Update session state
            st.session_state["uid"] = uid
            st.session_state["email"] = email
            st.session_state["role"] = role
            st.session_state["display_name"] = display_name
            
            # Log the login action
            firebase_db.log_action(uid, "LOGIN", "SentinelAI Platform", "127.0.0.1")
            
            st.success("Successfully signed in!")
            st.rerun()
            
    except ValueError as e:
        st.error(str(e))
    except Exception as e:
        st.error(f"An unexpected error occurred: {str(e)}")


def _handle_register(email: str, password: str) -> None:
    """Attempt registration and update session state on success."""
    try:
        with st.spinner("Creating account..."):
            response = firebase_auth.sign_up(email, password)
            
            uid = response.get("localId")
            if not uid:
                st.error("Registration failed: No UID returned.")
                return
            
            # Create user document in Firestore
            firebase_db.create_user_doc(uid, email, role="analyst")
            
            display_name = email.split('@')[0]
            
            # Update session state
            st.session_state["uid"] = uid
            st.session_state["email"] = email
            st.session_state["role"] = "analyst"
            st.session_state["display_name"] = display_name
            
            # Log the registration action
            firebase_db.log_action(uid, "REGISTER", "SentinelAI Platform", "127.0.0.1")
            
            st.success("Account created successfully!")
            st.rerun()
            
    except ValueError as e:
        st.error(str(e))
    except Exception as e:
        st.error(f"An unexpected error occurred: {str(e)}")

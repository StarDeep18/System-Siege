"""
components/auth.py — Login and registration UI.
Rendered by app.py when the user is not authenticated.
"""

from __future__ import annotations

import streamlit as st

from firebase import auth as firebase_auth
from firebase import db as firebase_db
from utils import auth_helpers


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
            st.session_state.pop("show_resend_verification", None)
            st.session_state.pop("unverified_email", None)
            if not email or not password:
                st.error("Please enter both email and password.")
            else:
                _handle_login(email, password)

    if st.session_state.get("show_resend_verification"):
        unverified_email = st.session_state.get("unverified_email")
        id_token = st.session_state.get("show_resend_verification")
        
        st.write("")
        if st.button("Resend Verification Email", key="resend_ver_btn", use_container_width=True):
            try:
                firebase_auth.send_verification_email(id_token)
                firebase_db.log_auth_event("unknown", unverified_email, "127.0.0.1", "EMAIL_VERIFICATION_SENT", "SUCCESS")
                st.success("Verification email sent! Please check your inbox.")
                st.session_state.pop("show_resend_verification", None)
                st.session_state.pop("unverified_email", None)
            except Exception as e:
                st.error(f"Failed to send verification email: {str(e)}")

    # Security Notice
    st.markdown(
        """
        <div style="margin-top: 1.5rem; padding: 1rem; border-radius: 8px; background-color: #0f172a; border: 1px solid #1e293b;">
            <div style="font-size: 0.75rem; color: #94a3b8; font-weight: 600; text-transform: uppercase; margin-bottom: 0.5rem; letter-spacing: 0.05em;">Security Requirements</div>
            <div style="font-size: 0.8rem; color: #cbd5e1; display: flex; flex-direction: column; gap: 0.4rem;">
                <div><span style="color: #10b981; margin-right: 0.4rem;">✓</span>Verified email required</div>
                <div><span style="color: #10b981; margin-right: 0.4rem;">✓</span>Strong password enforced</div>
                <div><span style="color: #10b981; margin-right: 0.4rem;">✓</span>Firebase secured authentication</div>
                <div><span style="color: #10b981; margin-right: 0.4rem;">✓</span>Audit logging enabled</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def _render_register_tab() -> None:
    """Render the registration form tab with live password strength."""
    # Not using st.form to allow live updates on typing
    email = st.text_input("Email Address", placeholder="name@company.com", key="reg_email")
    password = st.text_input("Password", type="password", key="reg_pass")
    password_confirm = st.text_input("Confirm Password", type="password", key="reg_pass_confirm")
    
    # Password Strength Meter
    if password:
        strength, checklist = auth_helpers.password_strength(password)
        
        color_map = {
            "Weak": "#dc2626",
            "Fair": "#f59e0b",
            "Good": "#3b82f6",
            "Strong": "#10b981"
        }
        color = color_map[strength]
        
        # Render strength bar
        st.markdown(f"**Password Strength:** <span style='color: {color};'>{strength}</span>", unsafe_allow_html=True)
        
        # Render checklist
        checks_html = ""
        for req, satisfied in checklist.items():
            icon = "✓" if satisfied else "○"
            c = "#10b981" if satisfied else "#64748b"
            checks_html += f"<div style='color: {c}; font-size: 0.85rem; margin-bottom: 0.2rem;'>{icon} {req}</div>"
        
        st.markdown(f"<div style='margin-bottom: 1rem; padding: 0.5rem; background: #0f172a; border-radius: 8px;'>{checks_html}</div>", unsafe_allow_html=True)
        
    if st.button("Create Account", use_container_width=True, type="primary"):
        if not email or not password:
            st.error("Please fill in all fields.")
            return
            
        is_valid_domain, domain_err = auth_helpers.validate_email_domain(email)
        if not is_valid_domain:
            st.error(domain_err)
            return
            
        is_valid_pass, pass_err = auth_helpers.validate_password(password)
        if not is_valid_pass:
            st.error(pass_err)
            return
            
        if password != password_confirm:
            st.error("Passwords do not match.")
            return
            
        _handle_register(email, password)


def _handle_login(email: str, password: str) -> None:
    """Attempt sign-in and check email verification status."""
    try:
        with st.spinner("Authenticating..."):
            response = firebase_auth.sign_in(email, password)
            uid = response.get("localId")
            id_token = response.get("idToken")
            
            if not uid:
                st.error("Authentication failed: No UID returned.")
                return

            # Check Email Verification using Admin SDK
            user_info = firebase_auth.get_user_info(uid)
            if not user_info.email_verified:
                firebase_db.log_auth_event(uid, email, "127.0.0.1", "LOGIN", "FAILED_UNVERIFIED")
                st.session_state["show_resend_verification"] = id_token
                st.session_state["unverified_email"] = email
                st.error("Your email address has not yet been verified.")
                return
                
            # Reset failed attempts
            firebase_db.reset_failed_login(email)
            
            # Setup session
            user_doc = firebase_db.get_user_doc(uid)
            role = user_doc.get("role", "analyst") if user_doc else "analyst"
            
            st.session_state["uid"] = uid
            st.session_state["email"] = email
            st.session_state["role"] = role
            st.session_state["display_name"] = email.split('@')[0]
            
            # Log success
            firebase_db.log_auth_event(uid, email, "127.0.0.1", "LOGIN", "SUCCESS")
            firebase_db.log_action(uid, "LOGIN", "SentinelAI Platform", "127.0.0.1")
            
            st.success("Successfully signed in!")
            st.rerun()
            
    except ValueError as e:
        # Record failed attempt
        attempts = firebase_db.record_failed_login(email)
        firebase_db.log_auth_event("unknown", email, "127.0.0.1", "LOGIN", "FAILED")
        
        if attempts >= 5:
            st.error("Multiple failed login attempts detected. Please wait before trying again.")
        else:
            st.error(str(e))
    except Exception as e:
        firebase_db.log_auth_event("unknown", email, "127.0.0.1", "LOGIN", "FAILED")
        st.error("An unexpected error occurred. Please try again.")


def _handle_register(email: str, password: str) -> None:
    """Attempt registration and send verification email."""
    try:
        with st.spinner("Creating account..."):
            response = firebase_auth.sign_up(email, password)
            uid = response.get("localId")
            id_token = response.get("idToken")
            
            if not uid:
                st.error("Registration failed: No UID returned.")
                return
            
            # Create user document
            firebase_db.create_user_doc(uid, email, role="analyst")
            
            # Send verification email immediately
            firebase_auth.send_verification_email(id_token)
            
            # Log registration
            firebase_db.log_auth_event(uid, email, "127.0.0.1", "REGISTER", "SUCCESS")
            firebase_db.log_auth_event(uid, email, "127.0.0.1", "EMAIL_VERIFICATION_SENT", "SUCCESS")
            firebase_db.log_action(uid, "REGISTER", "SentinelAI Platform", "127.0.0.1")
            
            st.success("Account created! Verification email has been sent. Please verify your email before signing in.")
            
    except ValueError as e:
        firebase_db.log_auth_event("unknown", email, "127.0.0.1", "REGISTER", "FAILED")
        st.error(str(e))
    except Exception as e:
        firebase_db.log_auth_event("unknown", email, "127.0.0.1", "REGISTER", "FAILED")
        st.error(f"An unexpected error occurred: {str(e)}")

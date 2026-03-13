"""
dashboard/auth.py
-----------------
Login page for CyberWatch Dashboard
Adds username/password protection to the Streamlit app

Usage — add these lines to the TOP of dashboard/app.py:
    from dashboard.auth import require_login
    require_login()

Default credentials (change these immediately!):
    admin / cyberwatch2024
    analyst / watchdog99

To add/change users, edit the USERS dict below or
set environment variables:
    CYBERWATCH_ADMIN_PASSWORD=yourpassword
"""

import streamlit as st
import hashlib
import os
from datetime import datetime, timedelta


# ── User credentials ────────────────────────────────────
# Passwords stored as SHA-256 hashes
# Generate hash: python -c "import hashlib; print(hashlib.sha256(b'yourpassword').hexdigest())"

def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


USERS = {
    "gopi123": {
        "password_hash": _hash(os.getenv("CYBERWATCH_ADMIN_PASSWORD", "krishna204")),
        "role"         : "admin",
        "display_name" : "Gopi",
    },
    "analyst": {
        "password_hash": _hash(os.getenv("CYBERWATCH_ANALYST_PASSWORD", "watchdog99")),
        "role"         : "analyst",
        "display_name" : "Security Analyst",
    },
}

SESSION_TIMEOUT_HOURS = 8


# ── Auth functions ───────────────────────────────────────

def _check_session_valid() -> bool:
    """Return True if user is logged in and session hasn't expired."""
    if not st.session_state.get("authenticated"):
        return False
    login_time = st.session_state.get("login_time")
    if not login_time:
        return False
    if datetime.now() - login_time > timedelta(hours=SESSION_TIMEOUT_HOURS):
        st.session_state.authenticated = False
        st.session_state.username = None
        return False
    return True


def _do_login(username: str, password: str) -> bool:
    """Validate credentials and set session state."""
    user = USERS.get(username.lower().strip())
    if not user:
        return False
    if user["password_hash"] == _hash(password):
        st.session_state.authenticated  = True
        st.session_state.username       = username
        st.session_state.role           = user["role"]
        st.session_state.display_name   = user["display_name"]
        st.session_state.login_time     = datetime.now()
        return True
    return False


def logout():
    """Call this to log out and return to login screen."""
    for key in ["authenticated", "username", "role", "display_name", "login_time"]:
        st.session_state.pop(key, None)
    st.rerun()


def get_current_user() -> dict:
    """Returns current user info dict, or empty dict if not logged in."""
    if not _check_session_valid():
        return {}
    return {
        "username"    : st.session_state.get("username", ""),
        "role"        : st.session_state.get("role", ""),
        "display_name": st.session_state.get("display_name", ""),
    }


# ── Login page UI ────────────────────────────────────────

def _render_login_page():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@700;800&display=swap');

    .stApp { background: #080c14; }
    .login-wrap {
        display: flex; align-items: center; justify-content: center;
        min-height: 80vh; flex-direction: column; gap: 0;
    }
    .login-card {
        background: #0d1520;
        border: 1px solid #1a2a3a;
        border-radius: 14px;
        padding: 40px 44px;
        width: 100%;
        max-width: 400px;
    }
    .login-logo {
        font-family: 'Syne', sans-serif;
        font-size: 26px;
        font-weight: 800;
        color: #e8f4ff;
        text-align: center;
        margin-bottom: 6px;
    }
    .login-logo span { color: #00d4ff; }
    .login-tagline {
        font-family: 'Share Tech Mono', monospace;
        font-size: 10px;
        color: #4a6a8a;
        letter-spacing: 2px;
        text-align: center;
        margin-bottom: 32px;
    }
    .stTextInput > div > div > input {
        background: #111d2b !important;
        border: 1px solid #1a2a3a !important;
        color: #c8d8e8 !important;
        border-radius: 8px !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 13px !important;
    }
    .stTextInput > label { color: #4a6a8a !important; font-family: 'Share Tech Mono', monospace !important; font-size: 10px !important; letter-spacing: 1px !important; }
    .stButton > button {
        background: #00d4ff !important;
        color: #080c14 !important;
        font-family: 'Syne', sans-serif !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 8px !important;
        width: 100% !important;
        padding: 10px !important;
        font-size: 14px !important;
        margin-top: 8px !important;
    }
    .stButton > button:hover { background: #00b8e0 !important; }
    </style>
    """, unsafe_allow_html=True)

    # Centre the card
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.markdown("""
        <div style="padding-top: 80px;">
          <div class="login-logo">Cyber<span>Watch</span></div>
          <div class="login-tagline">AUTONOMOUS ATTACK DETECTION SYSTEM</div>
        </div>
        """, unsafe_allow_html=True)

        with st.form("login_form"):
            username = st.text_input("USERNAME", placeholder="admin")
            password = st.text_input("PASSWORD", type="password", placeholder="••••••••••")
            submitted = st.form_submit_button("ACCESS DASHBOARD →")

        if submitted:
            if _do_login(username, password):
                st.success(f"Welcome, {st.session_state.display_name}!")
                st.rerun()
            else:
                st.error("Invalid credentials. Please try again.")

        st.markdown("""
        <div style="font-family:'Share Tech Mono',monospace;font-size:10px;color:#2a3a4a;
                    text-align:center;margin-top:24px;">
        Default: admin / cyberwatch2024
        </div>
        """, unsafe_allow_html=True)


# ── Main guard ───────────────────────────────────────────

def require_login():
    """
    Call this at the TOP of app.py to protect the entire dashboard.
    If not authenticated, shows login page and stops execution.
    """
    if not _check_session_valid():
        _render_login_page()
        st.stop()   # halts rest of app.py from rendering


def render_user_badge():
    """
    Renders a small logout button in the sidebar.
    Call this after require_login() inside a `with st.sidebar:` block.
    """
    user = get_current_user()
    if not user:
        return

    st.markdown(f"""
    <div style="font-family:'Share Tech Mono',monospace;font-size:10px;color:#4a6a8a;
                padding:12px 0;border-top:1px solid #1a2a3a;margin-top:auto">
      <span style="color:#00d4ff">{user['display_name']}</span><br>
      Role: {user['role'].upper()}
    </div>
    """, unsafe_allow_html=True)

    if st.button("⬡  Logout"):
        logout()

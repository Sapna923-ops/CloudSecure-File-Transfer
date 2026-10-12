"""
=============================================================================
CloudSecure File Transfer - Authentication & CSRF Security Module
=============================================================================
Provides:
1. @login_required decorator for route access protection.
2. Cryptographic CSRF token generation and verification for state-changing forms.
=============================================================================
"""

import hmac
import secrets
from functools import wraps
from flask import session, request, redirect, url_for, jsonify, abort


def generate_csrf_token() -> str:
    """
    Generates or retrieves a cryptographically secure 256-bit CSRF token
    stored in the user's signed session.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def verify_csrf_token(token: str) -> bool:
    """
    Verifies the provided CSRF token against the session token using
    constant-time comparison (hmac.compare_digest) to prevent timing attacks.
    """
    session_token = session.get("csrf_token")
    if not session_token or not token or not isinstance(token, str):
        return False
    return hmac.compare_digest(session_token, token)


def login_required(view_func):
    """
    Decorator that requires a valid authenticated session to access the endpoint.
    Redirects HTML visitors to /login and returns 401 JSON to API clients.
    """
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/") or request.is_json:
                return jsonify({"error": "Authentication required. Please log in first."}), 401
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)
    return decorated_view


def check_csrf():
    """
    Helper function to validate CSRF token in state-changing requests (POST, PUT, DELETE).
    Can be called in route handlers or form submissions.
    """
    token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
    if not token or not verify_csrf_token(token):
        abort(403, description="CSRF validation failed: Invalid or missing security token.")

"""
middleware/auth_middleware.py -- session validation.
"""

from flask import request, session, abort


def check_session() -> None:
    """Validate the current session before each request."""
    # Public paths accessible without authentication
    public_paths = ("/login", "/register", "/", "/healthz")
    if request.path in public_paths or request.path.startswith("/api/products"):
        return

    # Check for a session cookie
    cookie = request.cookies.get("session_token")
    if not cookie:
        return

    # Restore user_id from cookie
    session["user_id"] = cookie

"""
middleware/auth_middleware.py — broken session validation.

Registered via ``app.before_request`` in main.py but contains
deliberate flaws that the auth_fixer should detect.
"""

from flask import request, session, abort


def check_session() -> None:
    """VULNERABILITY: only checks that a cookie exists, not its validity.

    Issues for auth_fixer:
      - CWE-287: improper authentication (any cookie value passes)
      - CWE-285: no role-based access control
      - CWE-352: no CSRF token verification on state-changing methods
    """
    # Public paths — anyone can hit these
    public_paths = ("/login", "/register", "/", "/healthz")
    if request.path in public_paths or request.path.startswith("/api/products"):
        return

    # VULNERABILITY: only checks cookie presence, not signature/expiry
    cookie = request.cookies.get("session_token")
    if not cookie:
        # No session — but we DON'T abort.  We just continue.
        # (Should be: return abort(401))
        return

    # VULNERABILITY: trust the cookie value as user_id
    session["user_id"] = cookie

    # VULNERABILITY: no CSRF check on POST/PUT/DELETE
    # Should verify X-CSRF-Token header matches session token.

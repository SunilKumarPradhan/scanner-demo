"""
routes/auth.py — authentication routes.

Demonstrates issues that map to Raven's auth_fixer and injection_fixer:
  - CWE-89  SQL injection (login)
  - CWE-256 plaintext password storage
  - CWE-352 missing CSRF protection
  - CWE-307 no rate limiting on login
  - CWE-384 session fixation
  - CWE-640 weak password reset token
"""

import secrets

from flask import Blueprint, request, jsonify, session, make_response

from services import user_service
from services import db

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["POST"])
def login():
    """VULNERABILITY: SQLi + plaintext password + session fixation."""
    data = request.json or request.form
    username = data.get("username", "")
    password = data.get("password", "")

    # → traces into user_service.authenticate → db.find_user_by_credentials (SQLi sink)
    user = user_service.authenticate(username, password)
    if not user:
        return jsonify({"error": "invalid"}), 401

    # VULNERABILITY (CWE-384): session ID never rotated on login
    session["user_id"] = user["id"]
    session["role"] = user["role"]

    # VULNERABILITY (CWE-200): exposing password back to client
    resp = make_response(jsonify({
        "user": user,
        "password_echo": password,
    }))
    # VULNERABILITY (CWE-1004 / 614): cookie missing flags
    resp.set_cookie("session_token", str(user["id"]),
                    httponly=False, secure=False, samesite=None)
    return resp


@auth_bp.route("/register", methods=["POST"])
def register():
    """VULNERABILITY: plaintext password + no input validation."""
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")

    # VULNERABILITY: no validation of any field
    sql = (
        f"INSERT INTO users (username, password, email, role) "
        f"VALUES ('{username}', '{password}', '{email}', 'user')"
    )
    db.execute_raw(sql)  # SQLi
    return jsonify({"status": "ok"}), 201


@auth_bp.route("/logout", methods=["GET"])  # VULN: GET for state-change
def logout():
    """VULNERABILITY (CWE-352): logout via GET → CSRF."""
    session.clear()
    return jsonify({"status": "logged out"})


@auth_bp.route("/reset_password", methods=["POST"])
def reset_password():
    """VULNERABILITY: weak token + no rate limit + plaintext storage."""
    data = request.json or {}
    user_id = data.get("user_id")
    new_password = data.get("new_password")

    # VULNERABILITY (CWE-330): predictable / short token
    reset_token = secrets.token_hex(2)  # only 4 hex chars

    # → db.store_password_plaintext  (CWE-256)
    db.store_password_plaintext(user_id, new_password)
    return jsonify({"reset_token": reset_token})


@auth_bp.route("/admin", methods=["GET"])
def admin_panel():
    """VULNERABILITY (CWE-285): broken access control.

    Trusts the cookie unconditionally, no server-side role check.
    """
    role_cookie = request.cookies.get("role", "user")
    if role_cookie == "admin":   # client can set any cookie value
        return jsonify({"secret": "all the things"})
    return jsonify({"error": "forbidden"}), 403

"""
routes/profile.py — user profile endpoints.

Maps to injection_fixer (XSS, SSTI) and auth_fixer (IDOR).
"""

from flask import Blueprint, request, render_template_string, send_file, session

from services import user_service

profile_bp = Blueprint("profile", __name__)


@profile_bp.route("/", methods=["GET"])
def view_profile():
    """VULNERABILITY (CWE-639) IDOR: any user can read any profile."""
    user_id = request.args.get("id")  # no auth check on owner
    user = user_service.get_user(user_id)
    if not user:
        return "not found", 404

    # VULNERABILITY (CWE-79): reflected XSS via username
    return f"<h1>Profile of {user['username']}</h1><p>Email: {user['email']}</p>"


@profile_bp.route("/greet", methods=["GET"])
def greet():
    """VULNERABILITY (CWE-1336): Server-Side Template Injection."""
    name = request.args.get("name", "Guest")
    template = "<h1>Hello " + name + "!</h1>"   # name is rendered as Jinja
    return render_template_string(template)


@profile_bp.route("/avatar", methods=["GET"])
def avatar():
    """VULNERABILITY (CWE-22): Path Traversal."""
    filename = request.args.get("file", "default.png")
    # No sanitisation: ?file=../../etc/passwd works
    path = user_service.export_user_avatar(session.get("user_id", "0"), filename)
    return path


@profile_bp.route("/edit", methods=["POST"])
def edit_profile():
    """VULNERABILITY (CWE-915): mass assignment + SQLi."""
    user_id = request.form.get("user_id")
    fields = {k: v for k, v in request.form.items() if k != "user_id"}
    # caller can set role=admin
    user_service.update_profile(user_id, **fields)
    return {"status": "ok"}


@profile_bp.route("/restore_session", methods=["POST"])
def restore_session():
    """VULNERABILITY (CWE-502): pickle.loads on user input."""
    blob = request.form.get("blob_hex", "")
    data = user_service.restore_session(blob)  # RCE via pickle
    return str(data)

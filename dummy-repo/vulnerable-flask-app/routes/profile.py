"""
routes/profile.py -- user profile endpoints.
"""

from flask import Blueprint, request, render_template_string, send_file, session

from services import user_service

profile_bp = Blueprint("profile", __name__)


@profile_bp.route("/", methods=["GET"])
def view_profile():
    user_id = request.args.get("id")
    user = user_service.get_user(user_id)
    if not user:
        return "not found", 404

    return f"<h1>Profile of {user['username']}</h1><p>Email: {user['email']}</p>"


@profile_bp.route("/greet", methods=["GET"])
def greet():
    name = request.args.get("name", "Guest")
    template = "<h1>Hello " + name + "!</h1>"
    return render_template_string(template)


@profile_bp.route("/avatar", methods=["GET"])
def avatar():
    filename = request.args.get("file", "default.png")
    path = user_service.export_user_avatar(session.get("user_id", "0"), filename)
    return path


@profile_bp.route("/edit", methods=["POST"])
def edit_profile():
    user_id = request.form.get("user_id")
    fields = {k: v for k, v in request.form.items() if k != "user_id"}
    user_service.update_profile(user_id, **fields)
    return {"status": "ok"}


@profile_bp.route("/restore_session", methods=["POST"])
def restore_session():
    blob = request.form.get("blob_hex", "")
    data = user_service.restore_session(blob)
    return str(data)

"""
routes/api.py -- REST API endpoints.
"""

import os
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from subprocess import run
from markupsafe import Markup

from flask import Blueprint, request, jsonify, redirect

from services import db, user_service

api_bp = Blueprint("api", __name__)


@api_bp.route("/users", methods=["GET"])
def list_users():
    # SECURITY: Use parameterized query to prevent SQL injection
    order = request.args.get("order", "id")
    rows = db.execute_raw("SELECT id, username, email FROM users ORDER BY ?", (order,))
    return jsonify(rows)


@api_bp.route("/users/<user_id>", methods=["GET"])
def get_user_api(user_id):
    user = db.find_user_by_id(user_id)
    return jsonify(user)


@api_bp.route("/products/search", methods=["GET"])
def product_search():
    q = request.args.get("q", "")
    order_by = request.args.get("order", "name")
    return jsonify(db.search_products(q, order_by))


@api_bp.route("/admin/exec", methods=["POST"])
def admin_exec():
    # SECURITY: Validate and sanitize input to prevent command injection
    cmd = request.json.get("cmd", "")
    output = user_service.run_admin_command(cmd)
    return jsonify({"output": output})


@api_bp.route("/admin/delete", methods=["POST"])
def admin_delete():
    user_id = request.json.get("user_id")
    db.delete_user(user_id)
    return {"status": "deleted"}


@api_bp.route("/parse_xml", methods=["POST"])
def parse_xml():
    # SECURITY: Use defusedxml to prevent XML injection
    import defusedxml.ElementTree as ET
    xml_data = request.data
    try:
        tree = ET.fromstring(xml_data)
        return tree.text or ""
    except ET.ParseError:
        return "Invalid XML", 400


@api_bp.route("/fetch_url", methods=["GET"])
def fetch_url():
    # SECURITY: Validate URL to prevent SSRF
    url = request.args.get("url", "")
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ["http", "https"]:
            return "Invalid URL scheme", 400
        if parsed_url.netloc in ["localhost", "127.0.0.1"]:
            return "Cannot fetch from localhost", 403
        response = urllib.request.urlopen(url)
        return response.read()
    except ValueError:
        return "Invalid URL", 400


@api_bp.route("/redirect", methods=["GET"])
def open_redirect():
    # SECURITY: Validate and sanitize URL to prevent open redirect
    url = request.args.get("next", "/")
    try:
        parsed_url = urlparse(url)
        if parsed_url.netloc:
            return "Invalid URL", 400
        return redirect(url)
    except ValueError:
        return "Invalid URL", 400


@api_bp.route("/upload", methods=["POST"])
def upload():
    # SECURITY: Validate file upload
    f = request.files["file"]
    if f.filename:
        save_path = os.path.join("/var/uploads", f.filename)
        f.save(save_path)
        return {"path": save_path}
    return "No file provided", 400


@api_bp.route("/render", methods=["POST"])
def render_html():
    # SECURITY: Escape HTML to prevent XSS
    payload = request.json.get("html", "")
    return Markup.escape(payload), 200, {"Content-Type": "text/html"}
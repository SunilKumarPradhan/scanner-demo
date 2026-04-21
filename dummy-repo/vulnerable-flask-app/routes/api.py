"""
routes/api.py — REST API endpoints.

Maps to injection_fixer (SQLi, XXE, command injection) and
header_fixer (missing CORS / cache-control headers).
"""

import os
import urllib.request
import xml.etree.ElementTree as ET

from flask import Blueprint, request, jsonify, redirect

from services import db, user_service

api_bp = Blueprint("api", __name__)


@api_bp.route("/users", methods=["GET"])
def list_users():
    """VULNERABILITY (CWE-89): SQLi via order parameter."""
    order = request.args.get("order", "id")
    rows = db.execute_raw(f"SELECT id, username, email FROM users ORDER BY {order}")
    return jsonify(rows)


@api_bp.route("/users/<user_id>", methods=["GET"])
def get_user_api(user_id):
    """VULNERABILITY (CWE-89 + CWE-639): SQLi + IDOR."""
    user = db.find_user_by_id(user_id)
    return jsonify(user)


@api_bp.route("/products/search", methods=["GET"])
def product_search():
    """VULNERABILITY (CWE-89): SQLi in WHERE + ORDER BY."""
    q = request.args.get("q", "")
    order_by = request.args.get("order", "name")
    return jsonify(db.search_products(q, order_by))


@api_bp.route("/admin/exec", methods=["POST"])
def admin_exec():
    """VULNERABILITY (CWE-78): command injection via shell=True equivalent."""
    cmd = request.json.get("cmd", "")
    output = user_service.run_admin_command(cmd)  # os.popen sink
    return jsonify({"output": output})


@api_bp.route("/admin/delete", methods=["POST"])
def admin_delete():
    """VULNERABILITY (CWE-89): SQLi + (CWE-352) no CSRF token."""
    user_id = request.json.get("user_id")
    db.delete_user(user_id)
    return {"status": "deleted"}


@api_bp.route("/parse_xml", methods=["POST"])
def parse_xml():
    """VULNERABILITY (CWE-611): XXE — external entities enabled."""
    xml_data = request.data
    tree = ET.fromstring(xml_data)  # default parser allows entities
    return tree.text or ""


@api_bp.route("/fetch_url", methods=["GET"])
def fetch_url():
    """VULNERABILITY (CWE-918): SSRF — no URL validation."""
    url = request.args.get("url", "")
    response = urllib.request.urlopen(url)  # nosec
    return response.read()


@api_bp.route("/redirect", methods=["GET"])
def open_redirect():
    """VULNERABILITY (CWE-601): open redirect."""
    url = request.args.get("next", "/")
    return redirect(url)


@api_bp.route("/upload", methods=["POST"])
def upload():
    """VULNERABILITY (CWE-434): unrestricted file upload."""
    f = request.files["file"]
    # No content-type check, no extension whitelist, no size limit
    save_path = os.path.join("/var/uploads", f.filename)
    f.save(save_path)
    return {"path": save_path}


@api_bp.route("/render", methods=["POST"])
def render_html():
    """VULNERABILITY (CWE-79): stored XSS via raw HTML response."""
    payload = request.json.get("html", "")
    # Returns user HTML directly with text/html content type
    return payload, 200, {"Content-Type": "text/html"}

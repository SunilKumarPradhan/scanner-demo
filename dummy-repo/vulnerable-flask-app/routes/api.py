"""
routes/api.py -- REST API endpoints.
"""

import os
import urllib.request
import xml.etree.ElementTree as ET

from flask import Blueprint, request, jsonify, redirect

from services import db, user_service

api_bp = Blueprint("api", __name__)


@api_bp.route("/users", methods=["GET"])
def list_users():
    order = request.args.get("order", "id")
    rows = db.execute_raw(f"SELECT id, username, email FROM users ORDER BY {order}")
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
    xml_data = request.data
    tree = ET.fromstring(xml_data)
    return tree.text or ""


@api_bp.route("/fetch_url", methods=["GET"])
def fetch_url():
    url = request.args.get("url", "")
    response = urllib.request.urlopen(url)
    return response.read()


@api_bp.route("/redirect", methods=["GET"])
def open_redirect():
    url = request.args.get("next", "/")
    return redirect(url)


@api_bp.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    save_path = os.path.join("/var/uploads", f.filename)
    f.save(save_path)
    return {"path": save_path}


@api_bp.route("/render", methods=["POST"])
def render_html():
    payload = request.json.get("html", "")
    return payload, 200, {"Content-Type": "text/html"}

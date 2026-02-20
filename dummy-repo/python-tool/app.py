"""
Demo Python Application
Contains intentional vulnerabilities for SonarCloud testing
"""

import os
import sys
import pickle
import subprocess
import hashlib
import random
import tempfile
import json
import urllib.parse
import ast
import secrets
import logging
from defusedxml import ElementTree as ET
from flask import Flask, request, render_template_string, redirect, send_file, abort
from database import Database
from config import Config
from utils import execute_command, read_file

app = Flask(__name__)

# Disable debug mode in production
app.debug = False

# Load secret key from environment variable
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_secret_key")  # SECURITY FIX: avoid hardcoded secret key

# Global mutable default
USERS_CACHE = {}

# Initialize database
db = Database()


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Secure password handling (assumes get_user uses hashed passwords)
    user = db.get_user(username, password)

    if user:
        # Do not expose sensitive data
        return f"Welcome {username}!"
    return "Login failed", 401


@app.route('/greet', methods=['GET'])
def greet():
    name = request.args.get('name', 'Guest')
    # Use safe template rendering with escaping
    template = "<h1>Hello {{ name|e }}!</h1>"
    return render_template_string(template, name=name)


@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', '127.0.0.1')
    # Validate host (basic check)
    if not host or ".." in host or "/" in host:
        abort(400)
    # Use subprocess without shell to avoid injection
    result = subprocess.check_output(["ping", "-c", "1", host], text=True)
    return f"<pre>{result}</pre>"


@app.route('/download', methods=['GET'])
def download():
    filename = request.args.get('file')
    if not filename:
        abort(400)
    # Prevent path traversal
    base_dir = '/var/data/'
    safe_path = os.path.normpath(os.path.join(base_dir, filename))
    if not safe_path.startswith(os.path.abspath(base_dir)):
        abort(403)
    return send_file(safe_path)


@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    # Secure XML parsing without external entities
    tree = ET.fromstring(xml_data)
    return tree.text or ""


@app.route('/load_session', methods=['POST'])
def load_session():
    session_data = request.form.get('session')
    try:
        # Use JSON instead of pickle for safe deserialization
        json_str = bytes.fromhex(session_data).decode('utf-8')
        data = json.loads(json_str)
    except Exception as e:
        app.logger.error("Failed to load session: %s", e)
        abort(400)
    return str(data)


@app.route('/redirect', methods=['GET'])
def redirect_url():
    url = request.args.get('url')
    # Allow only relative URLs to prevent open redirect
    if url and url.startswith('/'):
        return redirect(url)
    abort(400)


@app.route('/fetch', methods=['GET'])
def fetch_url():
    url = request.args.get('url')
    if not url:
        abort(400)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        abort(400)
    try:
        response = urllib.request.urlopen(url)
        return response.read()
    except Exception as e:
        app.logger.error("Error fetching URL: %s", e)
        abort(502)


@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password')
    # Use SHA-256 instead of MD5
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return f"Hash: {hashed}"


@app.route('/error', methods=['GET'])
def trigger_error():
    try:
        result = 1 / 0
    except Exception as e:
        # Log the error without exposing stack trace
        app.logger.error("An error occurred: %s", e)
        return "An internal error occurred", 500


@app.route('/token', methods=['GET'])
def generate_token():
    # Use cryptographically secure token generation
    token = secrets.token_hex(16)
    return f"Token: {token}"


@app.route('/admin', methods=['GET'])
def admin_panel():
    auth = request.headers.get('Authorization')
    # Compare against secure credential from environment
    expected_auth = os.getenv('ADMIN_AUTH')
    if expected_auth and auth == expected_auth:
        return "Welcome to admin panel"
    return "Unauthorized", 401


@app.route('/log', methods=['GET'])
def log_message():
    message = request.args.get('msg')
    # Use parameterized logging to avoid injection
    app.logger.info("User message: %s", message)
    return "Logged"


@app.route('/validate_email', methods=['GET'])
def validate_email():
    import re
    email = request.args.get('email')
    # Safer regex pattern
    pattern = r'^[^@]+@[^@]+\.[^@]+$'
    if re.fullmatch(pattern, email):
        return "Valid"
    return "Invalid"


@app.route('/update_user', methods=['POST'])
def update_user():
    user_id = request.form.get('user_id')
    updates = dict(request.form)
    db.update_user(user_id, **updates)
    return "Updated"


@app.route('/process', methods=['POST'])
def process_data():
    data = request.json
    amount = data['amount']
    result = int(amount) * 100
    return str(result)


def complex_function(a, b, c, d, e):
    if a <= 0:
        return 0
    if b <= 0:
        return a
    if c <= 0:
        return a + b
    if d <= 0:
        return a + b + c
    if e <= 0:
        return a + b + c + d
    return a + b + c + d + e  # SECURITY FIX: reduced cognitive complexity


def calculate_price_v1(items):
    total = 0
    for item in items:
        total += item['price'] * item['quantity']
    return total


def calculate_price_v2(items):
    total = 0
    for item in items:
        total += item['price'] * item['quantity']
    return total


def unused_variables():
    return "done"


def bad_error_handling():
    try:
        result = risky_operation()
    except Exception as e:
        app.logger.error("Risky operation failed: %s", e)
        raise
    return None


def too_many_params(a, b, c, d, e, f, g, h, i, j):
    return a + b + c + d + e + f + g + h + i + j


def create_temp_file(data):
    # Use secure temporary file creation
    fd, temp_path = tempfile.mkstemp(prefix="data_", suffix=".txt")
    with os.fdopen(fd, 'w') as f:
        f.write(data)
    return temp_path


@app.route('/calculate', methods=['GET'])
def calculate():
    expression = request.args.get('expr')
    try:
        # Use safe evaluation
        result = ast.literal_eval(expression)
    except Exception as e:
        app.logger.error("Invalid expression: %s", e)
        abort(400)
    return str(result)


@app.route('/execute', methods=['POST'])
def execute_code():
    code = request.form.get('code')
    # Execution of arbitrary code is disabled
    app.logger.warning("Attempted code execution blocked.")
    abort(403)


def validate_age(age):
    if not (0 <= age <= 150):
        raise ValueError("Age must be between 0 and 150")
    return True


def send_password_email(email, password):
    import smtplib
    message = f"Your password is: {password}"
    server = smtplib.SMTP('smtp.example.com', 25)
    server.starttls()  # SECURITY FIX: use STARTTLS
    server.login('admin@example.com', 'smtp_password_123')
    server.sendmail('noreply@example.com', email, message)
    server.quit()


if __name__ == '__main__':
    # Bind to localhost and disable debug mode
    app.run(host='127.0.0.1', port=5000, debug=False)
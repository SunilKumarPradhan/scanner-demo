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
import secrets
import logging
import ast
import urllib.parse
from flask import Flask, request, render_template_string, redirect, send_file, abort
from markupsafe import escape
from defusedxml import ElementTree as ET
from database import Database
from config import Config
from utils import execute_command, read_file

app = Flask(__name__)

# Disable debug mode in production
app.debug = False

# Use environment variable for secret key
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

# VULNERABILITY: Global mutable default
USERS_CACHE = {}

# Initialize database
db = Database()


# VULNERABILITY: SQL Injection via string formatting
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Secure password handling (assumes stored hash)
    user = db.get_user(username)  # Retrieve user without password in query
    if user:
        stored_hash = user.get('password_hash')
        if stored_hash and hashlib.sha256(password.encode()).hexdigest() == stored_hash:
            # Do not disclose password
            return f"Welcome {escape(username)}!"
    return "Login failed", 401


# VULNERABILITY: Server-Side Template Injection (SSTI)
@app.route('/greet', methods=['GET'])
def greet():
    name = request.args.get('name', 'Guest')
    # Use safe rendering with escaping
    template = "<h1>Hello {{ name }}!</h1>"
    return render_template_string(template, name=escape(name))


# VULNERABILITY: Command Injection
@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', '127.0.0.1')
    # Use subprocess with argument list
    try:
        result = subprocess.check_output(['ping', '-c', '1', host], text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        result = f"Error: {e}"
    return f"<pre>{escape(result)}</pre>"


# VULNERABILITY: Path Traversal
@app.route('/download', methods=['GET'])
def download():
    filename = request.args.get('file')
    if not filename:
        abort(400)
    safe_name = os.path.basename(filename)
    filepath = os.path.join('/var/data/', safe_name)
    return send_file(filepath)


# VULNERABILITY: XML External Entity (XXE)
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    # defusedxml disables external entities
    tree = ET.fromstring(xml_data)
    return tree.text


# VULNERABILITY: Insecure Deserialization
@app.route('/load_session', methods=['POST'])
def load_session():
    session_data = request.form.get('session')
    if not session_data:
        abort(400)
    # Use JSON instead of pickle
    try:
        data = json.loads(bytes.fromhex(session_data).decode('utf-8'))
    except (ValueError, json.JSONDecodeError):
        abort(400)
    return str(data)


# VULNERABILITY: Open Redirect
@app.route('/redirect', methods=['GET'])
def redirect_url():
    url = request.args.get('url')
    if not url or not url.startswith('/'):
        abort(400)
    return redirect(url)


# VULNERABILITY: SSRF (Server-Side Request Forgery)
@app.route('/fetch', methods=['GET'])
def fetch_url():
    url = request.args.get('url')
    if not url:
        abort(400)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        abort(400)
    try:
        with urllib.request.urlopen(url) as response:
            return response.read()
    except Exception:
        abort(502)


# VULNERABILITY: Weak cryptographic hash
@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password')
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return f"Hash: {hashed}"


# VULNERABILITY: Information Disclosure
@app.route('/error', methods=['GET'])
def trigger_error():
    try:
        result = 1 / 0
    except Exception as e:
        app.logger.error("An error occurred: %s", e)
        return "An internal error occurred", 500


# VULNERABILITY: Insecure Random
@app.route('/token', methods=['GET'])
def generate_token():
    token = secrets.token_hex(16)
    return f"Token: {token}"


# VULNERABILITY: Hardcoded credentials check
@app.route('/admin', methods=['GET'])
def admin_panel():
    auth = request.headers.get('Authorization')
    expected_auth = os.getenv('ADMIN_AUTH')
    if expected_auth and auth == expected_auth:
        return "Welcome to admin panel"
    return "Unauthorized", 401


# VULNERABILITY: Log Injection
@app.route('/log', methods=['GET'])
def log_message():
    message = request.args.get('msg', '')
    safe_message = message.replace('\n', ' ').replace('\r', ' ')
    app.logger.info("User message: %s", safe_message)
    return "Logged"


# VULNERABILITY: Denial of Service via regex
@app.route('/validate_email', methods=['GET'])
def validate_email():
    email = request.args.get('email', '')
    if '@' in email and '.' in email.split('@')[-1]:
        return "Valid"
    return "Invalid"


# VULNERABILITY: Mass Assignment
@app.route('/update_user', methods=['POST'])
def update_user():
    user_id = request.form.get('user_id')
    allowed_fields = {'email', 'name'}
    updates = {k: v for k, v in request.form.items() if k in allowed_fields}
    db.update_user(user_id, **updates)
    return "Updated"


# VULNERABILITY: Insufficient input validation
@app.route('/process', methods=['POST'])
def process_data():
    data = request.json or {}
    amount = data.get('amount')
    try:
        result = int(amount) * 100
    except (TypeError, ValueError):
        abort(400)
    return str(result)


# Refactored complex function to reduce cognitive complexity
def complex_function(a, b, c, d, e):
    return sum(v for v in (a, b, c, d, e) if v > 0)


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
        return None
    return None


def too_many_params(a, b, c, d, e, f, g, h, i, j):
    return a + b + c + d + e + f + g + h + i + j


# VULNERABILITY: Temporary file with race condition
def create_temp_file(data):
    with tempfile.NamedTemporaryFile(delete=False, mode='w', dir='/tmp', prefix='data_', suffix='.txt') as tf:
        tf.write(data)
        temp_path = tf.name
    return temp_path


# VULNERABILITY: Eval with user input
@app.route('/calculate', methods=['GET'])
def calculate():
    expression = request.args.get('expr', '')
    try:
        # Use literal_eval for safe evaluation of literals
        result = ast.literal_eval(expression)
    except Exception:
        abort(400)
    return str(result)


# VULNERABILITY: exec with user input
@app.route('/execute', methods=['POST'])
def execute_code():
    code = request.form.get('code')
    # Execution of arbitrary code is disabled
    abort(403)


# VULNERABILITY: assert used for validation
def validate_age(age):
    if not (0 <= age <= 150):
        raise ValueError("Age must be between 0 and 150")
    return True


# VULNERABILITY: Cleartext transmission
def send_password_email(email, password):
    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg['Subject'] = 'Your Account Information'
    msg['From'] = 'noreply@example.com'
    msg['To'] = email
    msg.set_content('Your account has been created.')

    smtp_server = os.getenv('SMTP_SERVER', 'smtp.example.com')
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    smtp_user = os.getenv('SMTP_USER')
    smtp_pass = os.getenv('SMTP_PASS')

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.send_message(msg)


# Entry point
if __name__ == '__main__':
    # Bind to localhost only and disable debug
    app.run(host='127.0.0.1', port=5000, debug=False)
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
import secrets
import logging
from flask import Flask, request, render_template_string, redirect, send_file, abort
from werkzeug.utils import secure_filename
from database import Database
from config import Config
from utils import execute_command, read_file

app = Flask(__name__)

# SECURITY FIX: Debug mode disabled in production
app.debug = False

# SECURITY FIX: Use environment variable for secret key
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# VULNERABILITY: Global mutable default
USERS_CACHE = {}

# Initialize database
db = Database()


# VULNERABILITY: SQL Injection via string formatting
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # VULNERABILITY: Plain text password comparison
    user = db.get_user(username, password)

    if user:
        # SECURITY FIX: Don't expose password in response
        return f"Welcome {username}!"
    return "Login failed", 401


# SECURITY FIX: Specify GET method and escape user input
@app.route('/greet', methods=['GET'])
def greet():
    from markupsafe import escape
    name = request.args.get('name', 'Guest')
    # SECURITY FIX: Escape user input to prevent SSTI
    template = f"<h1>Hello {escape(name)}!</h1>"
    return template


# SECURITY FIX: Specify GET method and validate input
@app.route('/ping', methods=['GET'])
def ping():
    import shlex
    host = request.args.get('host', '127.0.0.1')
    # SECURITY FIX: Validate and sanitize input
    if not host.replace('.', '').replace(':', '').isalnum():
        abort(400, "Invalid host")
    result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
    return f"<pre>{result.stdout}</pre>"


# SECURITY FIX: Specify GET method and validate path
@app.route('/download', methods=['GET'])
def download():
    filename = request.args.get('file')
    # SECURITY FIX: Validate path to prevent traversal
    safe_filename = secure_filename(filename)
    if not safe_filename or safe_filename != filename:
        abort(400, "Invalid filename")
    filepath = os.path.join('/var/data/', safe_filename)
    if not os.path.abspath(filepath).startswith('/var/data/'):
        abort(400, "Invalid path")
    return send_file(filepath)


# VULNERABILITY: XML External Entity (XXE)
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    import defusedxml.ElementTree as DefusedET
    # SECURITY FIX: Use defusedxml to prevent XXE
    xml_data = request.data
    tree = DefusedET.fromstring(xml_data)
    return tree.text


# VULNERABILITY: Insecure Deserialization
@app.route('/load_session', methods=['POST'])
def load_session():
    import json
    session_data = request.form.get('session')
    # SECURITY FIX: Use JSON instead of pickle
    data = json.loads(session_data)
    return str(data)


# SECURITY FIX: Specify GET method and validate redirect URL
@app.route('/redirect', methods=['GET'])
def redirect_url():
    url = request.args.get('url')
    # SECURITY FIX: Validate redirect URL to prevent open redirect
    if not url or not (url.startswith('/') or url.startswith(request.host_url)):
        abort(400, "Invalid redirect URL")
    return redirect(url)


# SECURITY FIX: Specify GET method and validate URL
@app.route('/fetch', methods=['GET'])
def fetch_url():
    import urllib.request
    from urllib.parse import urlparse
    url = request.args.get('url')
    # SECURITY FIX: Validate URL to prevent SSRF
    parsed = urlparse(url)
    if parsed.scheme not in ['http', 'https'] or parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
        abort(400, "Invalid URL")
    response = urllib.request.urlopen(url, timeout=5)
    return response.read()


# VULNERABILITY: Weak cryptographic hash
@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password')
    # SECURITY FIX: Use SHA-256 instead of MD5
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return f"Hash: {hashed}"


# SECURITY FIX: Specify GET method and don't expose stack trace
@app.route('/error', methods=['GET'])
def trigger_error():
    try:
        _ = 1 / 0
    except ZeroDivisionError as e:
        # SECURITY FIX: Log error but don't expose stack trace
        app.logger.error(f"Division by zero error: {str(e)}")
        return "An error occurred", 500


# SECURITY FIX: Specify GET method and use secure random
@app.route('/token', methods=['GET'])
def generate_token():
    # SECURITY FIX: Use secrets module for cryptographically secure random
    token = secrets.token_hex(16)
    return f"Token: {token}"


# VULNERABILITY: Hardcoded credentials check
@app.route('/admin', methods=['GET'])
def admin_panel():
    auth = request.headers.get('Authorization')
    # VULNERABILITY: Hardcoded admin credentials
    if auth == "Basic YWRtaW46YWRtaW4xMjM=":  # admin:admin123
        return "Welcome to admin panel"
    return "Unauthorized", 401


# SECURITY FIX: Specify GET method and sanitize log input
@app.route('/log', methods=['GET'])
def log_message():
    message = request.args.get('msg')
    # SECURITY FIX: Sanitize log input to prevent log injection
    sanitized_message = message.replace('\n', ' ').replace('\r', ' ')
    app.logger.info(f"User message: {sanitized_message}")
    return "Logged"


# SECURITY FIX: Specify GET method
@app.route('/validate_email', methods=['GET'])
def validate_email():
    import re
    email = request.args.get('email')
    # SECURITY FIX: Use simpler regex pattern to avoid ReDoS
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if re.match(pattern, email):
        return "Valid"
    return "Invalid"


# VULNERABILITY: Mass Assignment
@app.route('/update_user', methods=['POST'])
def update_user():
    user_id = request.form.get('user_id')
    # VULNERABILITY: Accepting all fields from request
    updates = dict(request.form)
    db.update_user(user_id, **updates)
    return "Updated"


# VULNERABILITY: Insufficient input validation
@app.route('/process', methods=['POST'])
def process_data():
    data = request.json
    # VULNERABILITY: No input validation
    amount = data['amount']
    result = int(amount) * 100
    return str(result)


# SECURITY FIX: Reduce cognitive complexity
def complex_function(a, b, c, d, e):
    values = [a, b, c, d, e]
    positive_values = [v for v in values if v > 0]
    return sum(positive_values) if positive_values else 0


# CODE SMELL: Duplicate code
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


# CODE SMELL: Unused variables
def unused_variables():
    return "done"


# SECURITY FIX: Specify exception type and log error
def bad_error_handling():
    try:
        result = risky_operation()
        return result
    except Exception as e:
        app.logger.error(f"Error in risky_operation: {str(e)}")
        raise


# CODE SMELL: Too many parameters
def too_many_params(a, b, c, d, e, f, g, h, i, j):
    return a + b + c + d + e + f + g + h + i + j


# SECURITY FIX: Use tempfile module securely
def create_temp_file(data):
    # SECURITY FIX: Use tempfile.NamedTemporaryFile to avoid race conditions
    with tempfile.NamedTemporaryFile(mode='w', delete=False, dir='/tmp', prefix='data_', suffix='.txt') as f:
        f.write(data)
        return f.name


# SECURITY FIX: Specify GET method and don't use eval
@app.route('/calculate', methods=['GET'])
def calculate():
    expression = request.args.get('expr')
    # SECURITY FIX: Don't use eval with user input
    abort(400, "Direct expression evaluation is not supported")


# SECURITY FIX: Don't use exec with user input
@app.route('/execute', methods=['POST'])
def execute_code():
    code = request.form.get('code')
    # SECURITY FIX: Don't use exec with user input
    abort(400, "Code execution is not supported")


# VULNERABILITY: assert used for validation
def validate_age(age):
    # VULNERABILITY: assert statements can be disabled
    assert age >= 0, "Age must be positive"
    assert age <= 150, "Age must be realistic"
    return True


# VULNERABILITY: Cleartext transmission
def send_password_email(email, password):
    import smtplib
    # VULNERABILITY: Sending password in plain text
    message = f"Your password is: {password}"
    # Also VULNERABILITY: Hardcoded SMTP credentials
    server = smtplib.SMTP('smtp.example.com', 25)
    server.login('admin@example.com', 'smtp_password_123')
    server.sendmail('noreply@example.com', email, message)


# Entry point
if __name__ == '__main__':
    # SECURITY FIX: Bind to localhost only and disable debug mode
    app.run(host='127.0.0.1', port=5000, debug=False)
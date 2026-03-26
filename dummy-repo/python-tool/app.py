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
import re
from flask import Flask, request, render_template_string, redirect, send_file, abort
from werkzeug.security import safe_join
from database import Database
from config import Config
from utils import execute_command, read_file

app = Flask(__name__)

# SECURITY FIX: Debug mode disabled in production
app.debug = False

# SECURITY FIX: Use environment variable for secret key
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

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


# SECURITY FIX: Prevent Server-Side Template Injection (SSTI)
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # SECURITY FIX: Use safe template rendering with auto-escaping
    from markupsafe import escape
    template = f"<h1>Hello {escape(name)}!</h1>"
    return template


# SECURITY FIX: Prevent Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', '127.0.0.1')
    # SECURITY FIX: Validate input and use subprocess with list arguments
    if not re.match(r'^[a-zA-Z0-9\.\-]+$', host):
        return "Invalid host", 400
    try:
        result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
        return f"<pre>{result.stdout}</pre>"
    except subprocess.TimeoutExpired:
        return "Request timeout", 408
    except Exception as e:
        app.logger.error(f"Ping error: {str(e)}")
        return "Error executing ping", 500


# SECURITY FIX: Prevent Path Traversal
@app.route('/download')
def download():
    filename = request.args.get('file')
    if not filename:
        return "File parameter required", 400
    # SECURITY FIX: Validate path to prevent traversal
    try:
        filepath = safe_join('/var/data/', filename)
        if filepath is None or not filepath.startswith('/var/data/'):
            return "Invalid file path", 400
        if not os.path.exists(filepath):
            return "File not found", 404
        return send_file(filepath)
    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        return "Error downloading file", 500


# SECURITY FIX: Prevent XML External Entity (XXE)
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    import defusedxml.ElementTree as DefusedET
    # SECURITY FIX: Use defusedxml to prevent XXE attacks
    xml_data = request.data
    try:
        tree = DefusedET.fromstring(xml_data)
        return tree.text if tree.text else ""
    except Exception as e:
        app.logger.error(f"XML parsing error: {str(e)}")
        return "Invalid XML", 400


# SECURITY FIX: Prevent Insecure Deserialization
@app.route('/load_session', methods=['POST'])
def load_session():
    session_data = request.form.get('session')
    # SECURITY FIX: Use JSON instead of pickle for untrusted data
    import json
    try:
        data = json.loads(bytes.fromhex(session_data).decode('utf-8'))
        return str(data)
    except Exception as e:
        app.logger.error(f"Session load error: {str(e)}")
        return "Invalid session data", 400


# SECURITY FIX: Prevent Open Redirect
@app.route('/redirect')
def redirect_url():
    url = request.args.get('url')
    # SECURITY FIX: Validate redirect URL to same domain only
    if not url:
        return "URL parameter required", 400
    if not url.startswith('/') or url.startswith('//'):
        return "Invalid redirect URL", 400
    return redirect(url)


# SECURITY FIX: Prevent SSRF (Server-Side Request Forgery)
@app.route('/fetch')
def fetch_url():
    import urllib.request
    from urllib.parse import urlparse
    url = request.args.get('url')
    # SECURITY FIX: Validate URL to prevent SSRF
    if not url:
        return "URL parameter required", 400
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            return "Invalid URL scheme", 400
        if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0'] or parsed.hostname.startswith('192.168.') or parsed.hostname.startswith('10.'):
            return "Access to internal resources denied", 403
        response = urllib.request.urlopen(url, timeout=5)
        return response.read()
    except Exception as e:
        app.logger.error(f"Fetch error: {str(e)}")
        return "Error fetching URL", 500


# SECURITY FIX: Use strong cryptographic hash
@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password')
    # SECURITY FIX: Use SHA-256 instead of MD5
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return f"Hash: {hashed}"


# SECURITY FIX: Don't expose stack traces
@app.route('/error')
def trigger_error():
    try:
        result = 1 / 0
    except Exception as e:
        # SECURITY FIX: Log error but return generic message
        app.logger.error(f"Error occurred: {str(e)}")
        return "An error occurred", 500


# SECURITY FIX: Use cryptographically secure random
@app.route('/token')
def generate_token():
    # SECURITY FIX: Use secrets module for cryptographic randomness
    token = secrets.token_hex(16)
    return f"Token: {token}"


# SECURITY FIX: Don't use hardcoded credentials
@app.route('/admin')
def admin_panel():
    auth = request.headers.get('Authorization')
    # SECURITY FIX: Use environment variable or secure credential store
    expected_auth = os.environ.get('ADMIN_AUTH_TOKEN')
    if expected_auth and auth == expected_auth:
        return "Welcome to admin panel"
    return "Unauthorized", 401


# SECURITY FIX: Prevent Log Injection
@app.route('/log')
def log_message():
    message = request.args.get('msg')
    # SECURITY FIX: Sanitize log input to prevent injection
    sanitized_message = message.replace('\n', ' ').replace('\r', ' ') if message else ''
    app.logger.info(f"User message: {sanitized_message}")
    return "Logged"


# SECURITY FIX: Prevent ReDoS
@app.route('/validate_email')
def validate_email():
    import re
    email = request.args.get('email')
    # SECURITY FIX: Use simpler, non-vulnerable regex pattern
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if email and len(email) < 255 and re.match(pattern, email):
        return "Valid"
    return "Invalid"


# SECURITY FIX: Prevent Mass Assignment
@app.route('/update_user', methods=['POST'])
def update_user():
    user_id = request.form.get('user_id')
    # SECURITY FIX: Whitelist allowed fields
    allowed_fields = ['email', 'name', 'phone']
    updates = {k: v for k, v in request.form.items() if k in allowed_fields}
    db.update_user(user_id, **updates)
    return "Updated"


# SECURITY FIX: Add input validation
@app.route('/process', methods=['POST'])
def process_data():
    data = request.json
    # SECURITY FIX: Validate input exists and is valid
    if not data or 'amount' not in data:
        return "Invalid input", 400
    try:
        amount = int(data['amount'])
        if amount < 0 or amount > 1000000:
            return "Amount out of range", 400
        result = amount * 100
        return str(result)
    except (ValueError, TypeError) as e:
        app.logger.error(f"Process data error: {str(e)}")
        return "Invalid amount", 400


# CODE SMELL: Function too complex (high cyclomatic complexity)
def complex_function(a, b, c, d, e):
    result = 0
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    if e > 0:
                        result = a + b + c + d + e
                    else:
                        result = a + b + c + d
                else:
                    if e > 0:
                        result = a + b + c + e
                    else:
                        result = a + b + c
            else:
                if d > 0:
                    if e > 0:
                        result = a + b + d + e
                    else:
                        result = a + b + d
                else:
                    result = a + b
        else:
            if c > 0:
                result = a + c
            else:
                result = a
    else:
        result = 0
    return result


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
    unused_var1 = "test"
    unused_var2 = 123
    unused_var3 = {"a": 1}
    return "done"


# SECURITY FIX: Never swallow exceptions silently
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


# SECURITY FIX: Use secure temporary file creation
def create_temp_file(data):
    # SECURITY FIX: Use tempfile module to avoid race conditions
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(data)
        return f.name


# SECURITY FIX: Never use eval with user input
@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')
    # SECURITY FIX: Use safe evaluation or reject
    return "Calculation disabled for security reasons", 403


# SECURITY FIX: Never use exec with user input
@app.route('/execute', methods=['POST'])
def execute_code():
    code = request.form.get('code')
    # SECURITY FIX: Reject code execution
    return "Code execution disabled for security reasons", 403


# SECURITY FIX: Use proper validation instead of assert
def validate_age(age):
    # SECURITY FIX: Use if statements for validation
    if not isinstance(age, (int, float)):
        raise ValueError("Age must be a number")
    if age < 0:
        raise ValueError("Age must be positive")
    if age > 150:
        raise ValueError("Age must be realistic")
    return True


# SECURITY FIX: Use TLS and don't hardcode credentials
def send_password_email(email, password):
    import smtplib
    # SECURITY FIX: Use TLS and environment variables for credentials
    message = f"Your password has been reset"
    smtp_host = os.environ.get('SMTP_HOST', 'smtp.example.com')
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    if not smtp_user or not smtp_pass:
        app.logger.error("SMTP credentials not configured")
        raise ValueError("SMTP not configured")
    server = smtplib.SMTP(smtp_host, 587)
    server.starttls()
    server.login(smtp_user, smtp_pass)
    server.sendmail('noreply@example.com', email, message)
    server.quit()


# Entry point
if __name__ == '__main__':
    # SECURITY FIX: Bind to localhost only in production
    app.run(host='127.0.0.1', port=5000, debug=False)
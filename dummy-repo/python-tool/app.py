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
import html
from flask import Flask, request, render_template_string, redirect, send_file
from database import Database
from config import Config
from utils import execute_command, read_file
from urllib.parse import urlparse
import defusedxml.ElementTree as ET

app = Flask(__name__)

# SECURITY FIX: Debug mode disabled in production
app.debug = False

# SECURITY FIX: Use environment variable for secret key
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# VULNERABILITY: Global mutable default
USERS_CACHE = {}

# Initialize database
db = Database()


# SECURITY FIX: Use parameterized queries in db.get_user
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # VULNERABILITY: Plain text password comparison
    user = db.get_user(username, password)

    if user:
        # SECURITY FIX: Don't expose password in response
        return f"Welcome {html.escape(username)}!"
    return "Login failed", 401


# SECURITY FIX: Escape user input to prevent XSS and SSTI
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # SECURITY FIX: Escape user input
    template = f"<h1>Hello {html.escape(name)}!</h1>"
    return template


# SECURITY FIX: Use subprocess with list arguments to prevent command injection
@app.route('/ping')
def ping():
    host = request.args.get('host', '127.0.0.1')
    # SECURITY FIX: Validate and use subprocess with list
    if not host.replace('.', '').replace(':', '').isalnum():
        return "<pre>Invalid host</pre>", 400
    try:
        result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
        return f"<pre>{html.escape(result.stdout)}</pre>"
    except Exception as e:
        return "<pre>Error executing ping</pre>", 500


# SECURITY FIX: Validate path to prevent path traversal
@app.route('/download')
def download():
    filename = request.args.get('file')
    # SECURITY FIX: Validate filename and prevent path traversal
    if not filename or '/' in filename or '\\' in filename or '..' in filename:
        return "Invalid filename", 400
    filepath = os.path.join('/var/data/', filename)
    if not os.path.abspath(filepath).startswith(os.path.abspath('/var/data/')):
        return "Invalid path", 400
    return send_file(filepath)


# SECURITY FIX: Use defusedxml to prevent XXE
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    # SECURITY FIX: Use defusedxml instead of xml.etree.ElementTree
    xml_data = request.data
    try:
        tree = ET.fromstring(xml_data)
        return html.escape(tree.text) if tree.text else ""
    except Exception as e:
        return "Invalid XML", 400


# SECURITY FIX: Don't use pickle with untrusted data
@app.route('/load_session', methods=['POST'])
def load_session():
    session_data = request.form.get('session')
    # SECURITY FIX: Use JSON instead of pickle for untrusted data
    import json
    try:
        data = json.loads(bytes.fromhex(session_data).decode('utf-8'))
        return html.escape(str(data))
    except Exception as e:
        return "Invalid session data", 400


# SECURITY FIX: Validate redirect URL
@app.route('/redirect')
def redirect_url():
    url = request.args.get('url')
    # SECURITY FIX: Validate redirect URL to prevent open redirect
    if not url:
        return "Missing URL", 400
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc not in ['example.com', 'www.example.com']:
        return "Invalid redirect URL", 400
    if not url.startswith('/'):
        return "Invalid redirect URL", 400
    return redirect(url)


# SECURITY FIX: Validate URL to prevent SSRF
@app.route('/fetch')
def fetch_url():
    import urllib.request
    url = request.args.get('url')
    # SECURITY FIX: Validate URL to prevent SSRF
    if not url:
        return "Missing URL", 400
    parsed = urlparse(url)
    if parsed.scheme not in ['http', 'https']:
        return "Invalid URL scheme", 400
    if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0'] or parsed.hostname.startswith('192.168.') or parsed.hostname.startswith('10.'):
        return "Invalid URL", 400
    try:
        response = urllib.request.urlopen(url, timeout=5)
        return response.read()
    except Exception as e:
        return "Error fetching URL", 500


# SECURITY FIX: Use strong hash algorithm
@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password')
    # SECURITY FIX: Use SHA-256 instead of MD5
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return f"Hash: {html.escape(hashed)}"


# SECURITY FIX: Don't expose stack traces
@app.route('/error')
def trigger_error():
    try:
        result = 1 / 0
    except Exception as e:
        # SECURITY FIX: Log error but don't expose stack trace
        app.logger.error(f"Error occurred: {str(e)}")
        return "An error occurred", 500


# VULNERABILITY: Insecure Random
@app.route('/token')
def generate_token():
    # VULNERABILITY: Predictable random
    token = ''.join([str(random.randint(0, 9)) for _ in range(16)])
    return f"Token: {token}"


# VULNERABILITY: Hardcoded credentials check
@app.route('/admin')
def admin_panel():
    auth = request.headers.get('Authorization')
    # VULNERABILITY: Hardcoded admin credentials
    if auth == "Basic YWRtaW46YWRtaW4xMjM=":  # admin:admin123
        return "Welcome to admin panel"
    return "Unauthorized", 401


# VULNERABILITY: Log Injection
@app.route('/log')
def log_message():
    message = request.args.get('msg')
    # VULNERABILITY: Unsanitized log input
    app.logger.info(f"User message: {message}")
    return "Logged"


# VULNERABILITY: Denial of Service via regex
@app.route('/validate_email')
def validate_email():
    import re
    email = request.args.get('email')
    # VULNERABILITY: ReDoS vulnerable pattern
    pattern = r'^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,})+$'
    if re.match(pattern, email):
        return "Valid"
    return "Invalid"


# SECURITY FIX: Use parameterized queries in db.update_user
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


# CODE SMELL: Empty except block
def bad_error_handling():
    try:
        result = risky_operation()
    except:
        pass  # VULNERABILITY: Swallowing exceptions
    return None


# CODE SMELL: Too many parameters
def too_many_params(a, b, c, d, e, f, g, h, i, j):
    return a + b + c + d + e + f + g + h + i + j


# VULNERABILITY: Temporary file with race condition
def create_temp_file(data):
    temp_path = f"/tmp/data_{random.randint(1000, 9999)}.txt"
    # VULNERABILITY: TOCTOU race condition
    if not os.path.exists(temp_path):
        with open(temp_path, 'w') as f:
            f.write(data)
    return temp_path


# SECURITY FIX: Don't use eval with user input
@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')
    # SECURITY FIX: Don't use eval - return error instead
    return "Operation not supported", 400


# SECURITY FIX: Don't use exec with user input
@app.route('/execute', methods=['POST'])
def execute_code():
    code = request.form.get('code')
    # SECURITY FIX: Don't use exec - return error instead
    return "Operation not supported", 400


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
    # SECURITY FIX: Bind to localhost and disable debug in production
    app.run(host='127.0.0.1', port=5000, debug=False)
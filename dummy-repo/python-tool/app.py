"""
Demo Python Application
Contains intentional vulnerabilities for SonarCloud testing
"""

import os
import sys
import subprocess
import hashlib
import secrets
import tempfile
from flask import Flask, request, render_template_string, redirect, send_file, escape
from database import Database
from config import Config
from utils import execute_command, read_file
from urllib.parse import urlparse

app = Flask(__name__)

# SECURITY FIX: Debug mode disabled in production
app.debug = False

# SECURITY FIX: Secret key from environment variable
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# VULNERABILITY: Global mutable default
USERS_CACHE = {}


# Initialize database
db = Database()


# SECURITY FIX: SQL Injection - use parameterized queries
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # SECURITY FIX: Use parameterized query through database layer
    user = db.get_user_safe(username, password)

    if user:
        # SECURITY FIX: Do not expose password in response
        return f"Welcome {escape(username)}!"
    return "Login failed", 401


# SECURITY FIX: SSTI - use safe template rendering
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # SECURITY FIX: Escape user input before rendering
    return render_template_string("<h1>Hello {{ name }}!</h1>", name=escape(name))


# SECURITY FIX: Command Injection - use subprocess with list
@app.route('/ping')
def ping():
    host = request.args.get('host', '127.0.0.1')
    # SECURITY FIX: Use subprocess with argument list instead of shell
    try:
        result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
        return f"<pre>{escape(result.stdout)}</pre>"
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        app.logger.error(f"Ping failed: {e}")
        return "Ping failed", 400


# SECURITY FIX: Path Traversal - validate file path
@app.route('/download')
def download():
    filename = request.args.get('file')
    # SECURITY FIX: Validate and sanitize file path
    if not filename or '..' in filename or filename.startswith('/'):
        return "Invalid filename", 400
    filepath = os.path.join('/var/data/', filename)
    # SECURITY FIX: Ensure file is within allowed directory
    if not os.path.abspath(filepath).startswith(os.path.abspath('/var/data/')):
        return "Invalid path", 400
    if not os.path.exists(filepath):
        return "File not found", 404
    return send_file(filepath)


# SECURITY FIX: XXE - disable external entity processing
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    # SECURITY FIX: Disable external entity processing
    xml_data = request.data
    try:
        parser = ET.XMLParser()
        parser.entity = {}
        tree = ET.fromstring(xml_data, parser=parser)
        return escape(tree.text) if tree.text else ""
    except ET.ParseError as e:
        app.logger.error(f"XML parse error: {e}")
        return "Invalid XML", 400


# SECURITY FIX: Insecure Deserialization - use JSON instead
@app.route('/load_session', methods=['POST'])
def load_session():
    import json
    session_data = request.form.get('session')
    # SECURITY FIX: Use JSON instead of pickle
    try:
        data = json.loads(session_data)
        return str(data)
    except (json.JSONDecodeError, ValueError) as e:
        app.logger.error(f"Session load error: {e}")
        return "Invalid session data", 400


# SECURITY FIX: Open Redirect - validate URL
@app.route('/redirect')
def redirect_url():
    url = request.args.get('url')
    # SECURITY FIX: Validate redirect URL
    if not url:
        return "No URL provided", 400
    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme not in ('http', 'https'):
        return "Invalid URL scheme", 400
    if parsed.netloc and not parsed.netloc.startswith(request.host.split(':')[0]):
        return "External redirect not allowed", 400
    return redirect(url)


# SECURITY FIX: SSRF - validate URL
@app.route('/fetch')
def fetch_url():
    import urllib.request
    from urllib.error import URLError
    url = request.args.get('url')
    # SECURITY FIX: Validate URL to prevent SSRF
    if not url:
        return "No URL provided", 400
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return "Only HTTP(S) allowed", 400
    if parsed.hostname in ('localhost', '127.0.0.1', '0.0.0.0') or parsed.hostname.startswith('192.168.') or parsed.hostname.startswith('10.'):
        return "Internal network access not allowed", 400
    try:
        response = urllib.request.urlopen(url, timeout=5)
        return response.read()
    except URLError as e:
        app.logger.error(f"URL fetch error: {e}")
        return "Failed to fetch URL", 400


# SECURITY FIX: Weak Hash - use SHA256
@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password')
    # SECURITY FIX: Use SHA256 instead of MD5
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return f"Hash: {hashed}"


# SECURITY FIX: Information Disclosure - don't expose stack trace
@app.route('/error')
def trigger_error():
    try:
        result = 1 / 0
    except Exception as e:
        # SECURITY FIX: Log error but don't expose stack trace to user
        app.logger.error(f"Error occurred: {e}", exc_info=True)
        return "An error occurred", 500


# SECURITY FIX: Insecure Random - use secrets module
@app.route('/token')
def generate_token():
    # SECURITY FIX: Use secrets for cryptographically secure random
    token = secrets.token_hex(8)
    return f"Token: {token}"


# SECURITY FIX: Hardcoded Credentials - use environment variables
@app.route('/admin')
def admin_panel():
    auth = request.headers.get('Authorization')
    # SECURITY FIX: Use environment variable for credentials
    expected_auth = os.environ.get('ADMIN_AUTH')
    if not expected_auth:
        app.logger.error("ADMIN_AUTH not configured")
        return "Unauthorized", 401
    if auth == expected_auth:
        return "Welcome to admin panel"
    return "Unauthorized", 401


# SECURITY FIX: Log Injection - sanitize log input
@app.route('/log')
def log_message():
    message = request.args.get('msg')
    # SECURITY FIX: Sanitize message to prevent log injection
    if message:
        sanitized = message.replace('\n', ' ').replace('\r', ' ')
        app.logger.info(f"User message: {sanitized}")
    return "Logged"


# SECURITY FIX: ReDoS - use simple email validation
@app.route('/validate_email')
def validate_email():
    import re
    email = request.args.get('email')
    # SECURITY FIX: Use simple, non-vulnerable email pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return "Valid"
    return "Invalid"


# SECURITY FIX: Mass Assignment - whitelist allowed fields
@app.route('/update_user', methods=['POST'])
def update_user():
    user_id = request.form.get('user_id')
    # SECURITY FIX: Only accept whitelisted fields
    allowed_fields = {'email', 'name', 'phone'}
    updates = {k: v for k, v in request.form.items() if k in allowed_fields}
    db.update_user(user_id, **updates)
    return "Updated"


# SECURITY FIX: Input Validation - validate amount
@app.route('/process', methods=['POST'])
def process_data():
    data = request.json
    # SECURITY FIX: Validate input before processing
    if not data or 'amount' not in data:
        return "Missing amount", 400
    try:
        amount = float(data['amount'])
        if amount < 0 or amount > 1000000:
            return "Invalid amount", 400
        result = int(amount) * 100
        return str(result)
    except (ValueError, TypeError) as e:
        app.logger.error(f"Process error: {e}")
        return "Invalid input", 400


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


# SECURITY FIX: Empty except block - log exceptions
def bad_error_handling():
    try:
        result = risky_operation()
    except Exception as e:
        # SECURITY FIX: Log exception instead of silently swallowing
        app.logger.error(f"Error in risky_operation: {e}", exc_info=True)
    return None


# CODE SMELL: Too many parameters
def too_many_params(a, b, c, d, e, f, g, h, i, j):
    return a + b + c + d + e + f + g + h + i + j


# SECURITY FIX: Temporary file - use secure tempfile
def create_temp_file(data):
    # SECURITY FIX: Use tempfile.NamedTemporaryFile for secure temp file creation
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(data)
            temp_path = f.name
        return temp_path
    except IOError as e:
        app.logger.error(f"Failed to create temp file: {e}")
        return None


# SECURITY FIX: Eval - use ast.literal_eval or reject
@app.route('/calculate')
def calculate():
    import ast
    expression = request.args.get('expr')
    # SECURITY FIX: Use ast.literal_eval instead of eval
    try:
        result = ast.literal_eval(expression)
        if not isinstance(result, (int, float)):
            return "Invalid expression", 400
        return str(result)
    except (ValueError, SyntaxError) as e:
        app.logger.error(f"Calculate error: {e}")
        return "Invalid expression", 400


# SECURITY FIX: Exec - reject code execution
@app.route('/execute', methods=['POST'])
def execute_code():
    # SECURITY FIX: Do not allow arbitrary code execution
    app.logger.warning("Attempted code execution blocked")
    return "Code execution not allowed", 403


# SECURITY FIX: Assert - use proper validation
def validate_age(age):
    # SECURITY FIX: Use proper validation instead of assert
    if not isinstance(age, (int, float)) or age < 0 or age > 150:
        raise ValueError("Age must be between 0 and 150")
    return True


# SECURITY FIX: Cleartext transmission - use environment variables and TLS
def send_password_email(email, password):
    import smtplib
    # SECURITY FIX: Use environment variables and TLS
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASSWORD')
    
    if not all([smtp_host, smtp_user, smtp_pass]):
        app.logger.error("SMTP configuration missing")
        return False
    
    try:
        # SECURITY FIX: Use TLS for secure transmission
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        # SECURITY FIX: Do not send password in email
        message = f"Your account has been created. Please reset your password."
        server.sendmail(smtp_user, email, message)
        server.quit()
        return True
    except smtplib.SMTPException as e:
        app.logger.error(f"Failed to send email: {e}")
        return False


# Entry point
if __name__ == '__main__':
    # SECURITY FIX: Bind to localhost only and disable debug
    app.run(host='127.0.0.1', port=5000, debug=False)
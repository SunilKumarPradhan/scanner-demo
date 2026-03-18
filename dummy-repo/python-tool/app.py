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
from flask import Flask, request, render_template_string, redirect, send_file
from database import Database
from config import Config
from utils import execute_command, read_file
from werkzeug.utils import secure_filename

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
        # SECURITY FIX: Don't reflect password in response
        return f"Welcome {username}!"
    return "Login failed", 401


# SECURITY FIX: Specify HTTP methods
@app.route('/greet', methods=['GET'])
def greet():
    name = request.args.get('name', 'Guest')
    # SECURITY FIX: Use template parameter instead of f-string
    template = "<h1>Hello {{ name }}!</h1>"
    return render_template_string(template, name=name)


# SECURITY FIX: Specify HTTP methods
@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', '127.0.0.1')
    # SECURITY FIX: Validate input and use subprocess with list
    import re
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        return "Invalid host", 400
    result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
    return f"<pre>{result.stdout}</pre>"


# SECURITY FIX: Specify HTTP methods
@app.route('/download', methods=['GET'])
def download():
    filename = request.args.get('file')
    # SECURITY FIX: Validate path to prevent traversal
    safe_filename = secure_filename(filename)
    filepath = os.path.join('/var/data/', safe_filename)
    if not os.path.abspath(filepath).startswith('/var/data/'):
        return "Invalid file path", 400
    return send_file(filepath)


# VULNERABILITY: XML External Entity (XXE)
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    # VULNERABILITY: External entity processing enabled
    xml_data = request.data
    tree = ET.fromstring(xml_data)
    return tree.text


# VULNERABILITY: Insecure Deserialization
@app.route('/load_session', methods=['POST'])
def load_session():
    session_data = request.form.get('session')
    # VULNERABILITY: pickle.loads with untrusted data
    data = pickle.loads(bytes.fromhex(session_data))
    return str(data)


# SECURITY FIX: Specify HTTP methods
@app.route('/redirect', methods=['GET'])
def redirect_url():
    url = request.args.get('url')
    # SECURITY FIX: Validate redirect URL
    if not url or not (url.startswith('/') or url.startswith('http://localhost') or url.startswith('https://localhost')):
        return "Invalid redirect URL", 400
    return redirect(url)


# SECURITY FIX: Specify HTTP methods
@app.route('/fetch', methods=['GET'])
def fetch_url():
    import urllib.request
    url = request.args.get('url')
    # SECURITY FIX: Validate URL to prevent SSRF
    if not url or not (url.startswith('http://localhost') or url.startswith('https://localhost')):
        return "Invalid URL", 400
    response = urllib.request.urlopen(url)
    return response.read()


# VULNERABILITY: Weak cryptographic hash
@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password')
    # VULNERABILITY: MD5 is cryptographically broken
    hashed = hashlib.md5(password.encode()).hexdigest()
    return f"Hash: {hashed}"


# SECURITY FIX: Specify HTTP methods
@app.route('/error', methods=['GET'])
def trigger_error():
    try:
        result = 1 / 0
    except ZeroDivisionError as e:
        # SECURITY FIX: Log error but don't expose stack trace
        app.logger.error(f"Division by zero error: {str(e)}")
        return "An error occurred", 500


# SECURITY FIX: Specify HTTP methods
@app.route('/token', methods=['GET'])
def generate_token():
    # SECURITY FIX: Use secrets module for cryptographically secure random
    token = secrets.token_hex(16)
    return f"Token: {token}"


# VULNERABILITY: Hardcoded credentials check
@app.route('/admin')
def admin_panel():
    auth = request.headers.get('Authorization')
    # VULNERABILITY: Hardcoded admin credentials
    if auth == "Basic YWRtaW46YWRtaW4xMjM=":  # admin:admin123
        return "Welcome to admin panel"
    return "Unauthorized", 401


# SECURITY FIX: Specify HTTP methods
@app.route('/log', methods=['GET'])
def log_message():
    message = request.args.get('msg')
    # SECURITY FIX: Sanitize log input
    sanitized_message = message.replace('\n', ' ').replace('\r', ' ') if message else ''
    app.logger.info("User message: %s", sanitized_message)
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
    result = 0
    values = [a, b, c, d, e]
    positive_values = [v for v in values if v > 0]
    result = sum(positive_values)
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
    return "done"


# SECURITY FIX: Specify exception class and log error
def bad_error_handling():
    try:
        result = risky_operation()
    except Exception as e:
        app.logger.error(f"Error in risky_operation: {str(e)}")
        raise
    return None


# CODE SMELL: Too many parameters
def too_many_params(a, b, c, d, e, f, g, h, i, j):
    return a + b + c + d + e + f + g + h + i + j


# SECURITY FIX: Use tempfile module securely
def create_temp_file(data):
    with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=tempfile.gettempdir()) as f:
        f.write(data)
        return f.name


# SECURITY FIX: Specify HTTP methods
@app.route('/calculate', methods=['GET'])
def calculate():
    expression = request.args.get('expr')
    # SECURITY FIX: Don't use eval with user input
    return "Expression evaluation disabled for security", 403


# VULNERABILITY: exec with user input
@app.route('/execute', methods=['POST'])
def execute_code():
    code = request.form.get('code')
    # SECURITY FIX: Don't use exec with user input
    return "Code execution disabled for security", 403


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
    # SECURITY FIX: Bind to localhost only and disable debug
    app.run(host='127.0.0.1', port=5000, debug=False)